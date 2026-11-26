//! Pruebas de integracion del relay en loopback (127.0.0.1, puerto efimero, sin red externa):
//! dos clientes reales, el handshake a traves del relay, aborto por contrasena erronea,
//! relay ciego, limite por IP, expiracion de slots, streams unidireccionales de video (copia exacta
//! y opaca, cierre al caer un extremo, tope y contrapresion) y canal partido en dos mitades.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use awawa_protocol::framing::encode_frame;
use awawa_protocol::wire::{decode_message, encode_message};
use awawa_protocol::{
    ConsentError, HandshakeError, HostAuthReply, HostAuthenticated, OperatorConnectionRequest,
    OperatorHandshake, OperatorSession, PakeChallenge, PakeConfirm, PakeHello, ScopedCapabilities,
    SessionId, WaitingForRequest,
};
use awawa_relay::{
    BridgeDirection, ByteTap, ClientError, ClientRequest, MAX_VIDEO_STREAMS, RelayClient,
    RelayClock, RelayConfig, RelayError, RelayHandle, RelayIdentity, RelayPin, RelayResponse,
    RelayServer, RelayedStream, StreamError, VideoReceiver,
};
use governor::clock::FakeRelativeClock;

type Captured = Arc<Mutex<Vec<(BridgeDirection, Vec<u8>)>>>;

struct TestRelay {
    addr: SocketAddr,
    pin: RelayPin,
    handle: RelayHandle,
}

impl TestRelay {
    fn client(&self) -> RelayClient {
        RelayClient::new(self.addr, self.pin.clone()).expect("cliente del relay")
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

fn start(config: RelayConfig) -> TestRelay {
    let identity = RelayIdentity::generate().expect("identidad");
    let server =
        RelayServer::bind("127.0.0.1:0".parse().unwrap(), &identity, config).expect("bind");
    let addr = server.local_addr().expect("direccion local");
    let handle = server.handle();
    tokio::spawn(server.run());
    TestRelay {
        addr,
        pin: identity.pin(),
        handle,
    }
}

fn sid(text: &str) -> SessionId {
    SessionId::parse(text).expect("ID valido")
}

async fn send_msg<T: serde::Serialize>(stream: &mut RelayedStream, msg: &T) {
    stream
        .send_frame(&encode_message(msg).unwrap())
        .await
        .expect("enviar trama");
}

async fn recv_msg<T: serde::de::DeserializeOwned>(stream: &mut RelayedStream) -> T {
    let bytes = stream.recv_frame().await.expect("recibir trama");
    decode_message(&bytes).expect("mensaje valido")
}

/// Host: recibe hello, responde challenge, verifica la confirmacion y envia el veredicto.
async fn host_handshake(
    waiting: WaitingForRequest,
    stream: &mut RelayedStream,
) -> Result<HostAuthenticated, (WaitingForRequest, ConsentError)> {
    let hello: PakeHello = recv_msg(stream).await;
    let (authenticating, challenge) = waiting.accept_operator_hello(&hello)?;
    send_msg(stream, &challenge).await;
    let confirm: PakeConfirm = recv_msg(stream).await;
    match authenticating.verify_operator_confirmation(&confirm, Instant::now()) {
        Ok(host) => {
            send_msg(stream, &host.reply).await;
            Ok(host)
        }
        Err((waiting, error, reply)) => {
            send_msg(stream, &reply).await;
            // El host no usara mas este canal: cierra con gracia para que el veredicto llegue.
            stream.finish().await;
            Err((waiting, error))
        }
    }
}

struct OperatorOutcome {
    result: Result<OperatorSession, HandshakeError>,
    /// Desde que el operador envia su confirmacion hasta que recibe el veredicto.
    verdict_time: Duration,
    /// Desde que empieza el handshake (hello) hasta el veredicto.
    total_time: Duration,
}

async fn operator_handshake(
    stream: &mut RelayedStream,
    session_id: SessionId,
    password: &str,
) -> OperatorOutcome {
    let started = Instant::now();
    let request = OperatorConnectionRequest {
        target_session_id: session_id,
        operator_display_name: "Soporte Nivel 2".to_string(),
        operator_ed25519_fingerprint: [9; 8],
        requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
    };
    let (operator, hello) = OperatorHandshake::start(&request, password).expect("inicio");
    send_msg(stream, &hello).await;
    let challenge: PakeChallenge = recv_msg(stream).await;
    let (awaiting, confirm) = operator.handle_challenge(&challenge).expect("challenge");
    let confirm_sent = Instant::now();
    send_msg(stream, &confirm).await;
    let reply: HostAuthReply = recv_msg(stream).await;
    let verdict_time = confirm_sent.elapsed();
    let result = awaiting.finish(&reply);
    OperatorOutcome {
        result,
        verdict_time,
        total_time: started.elapsed(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_through_relay_and_relay_stays_blind() {
    // Hook de inspeccion: captura TODO lo que el relay retransmite, en ambos sentidos.
    let captured: Captured = Arc::default();
    let sink = captured.clone();
    let tap: ByteTap = Arc::new(move |dir, bytes| {
        sink.lock().unwrap().push((dir, bytes.to_vec()));
    });
    let relay = start(RelayConfig {
        tap: Some(tap),
        ..RelayConfig::default()
    });

    let waiting = WaitingForRequest::start_client_reception().unwrap();
    let session_id = waiting.session_id();
    let password = waiting.display_password();

    let host_client = relay.client();
    let operator_client = relay.client();
    let registration = host_client
        .register_host(session_id)
        .await
        .expect("registro");
    assert_eq!(registration.ttl, Duration::from_secs(600));

    let host_task = tokio::spawn(async move {
        let mut stream = registration.wait_for_operator().await.expect("emparejado");
        let host = host_handshake(waiting, &mut stream)
            .await
            .expect("handshake del host");
        (stream, host)
    });
    let mut op_stream = operator_client
        .connect_operator(session_id)
        .await
        .expect("lookup");
    let outcome = operator_handshake(&mut op_stream, session_id, &password.to_lowercase()).await;
    let mut operator = outcome.result.expect("operador autenticado");
    let (mut host_stream, host) = host_task.await.unwrap();
    let sas = host.pending.sas();
    assert_eq!(
        sas, operator.sas,
        "mismo SAS en ambos lados a traves del relay"
    );
    let mut host_channel = host.channel;

    // Registros cifrados en ambos sentidos a traves del relay.
    let op_plain = b"mover cursor a (300,200): texto secreto del operador";
    let host_plain = b"fotograma de video: contenido secreto del host";
    let record = operator.channel.seal(op_plain).unwrap();
    op_stream.send_frame(&record).await.unwrap();
    let received = host_stream.recv_frame().await.unwrap();
    assert_eq!(host_channel.open(&received).unwrap(), op_plain);
    let record = host_channel.seal(host_plain).unwrap();
    host_stream.send_frame(&record).await.unwrap();
    let received = op_stream.recv_frame().await.unwrap();
    assert_eq!(operator.channel.open(&received).unwrap(), host_plain);

    // El relay no tiene acceso a la clave: nada de lo retransmitido contiene la contrasena (en
    // ninguna forma normalizada), el SAS ni el texto plano de los mensajes.
    let all: Vec<u8> = captured
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    let normalized = password.replace('-', "");
    let forbidden: Vec<(&str, Vec<u8>)> = vec![
        ("contrasena formateada", password.clone().into_bytes()),
        ("contrasena sin guion", normalized.clone().into_bytes()),
        (
            "contrasena en minusculas",
            password.to_lowercase().into_bytes(),
        ),
        (
            "contrasena sin guion en minusculas",
            normalized.to_lowercase().into_bytes(),
        ),
        (
            "contrasena con espacio",
            password.replace('-', " ").into_bytes(),
        ),
        ("SAS", sas.as_bytes().to_vec()),
        ("texto plano del operador", op_plain.to_vec()),
        ("texto plano del host", host_plain.to_vec()),
    ];
    for (what, needle) in &forbidden {
        assert!(!contains(&all, needle), "el relay vio: {what}");
    }
    // El hook funciona: ve el hello y los registros cifrados que si debe retransmitir.
    assert_eq!(
        captured.lock().unwrap()[0].0,
        BridgeDirection::OperatorToHost
    );
    assert!(
        contains(&all, &received),
        "el relay retransmite el registro cifrado tal cual"
    );
    assert!(all.len() > 300, "se capturo el handshake completo");

    // Cierre ordenado: el operador cierra su sentido y el host ve el fin del stream.
    op_stream.finish().await;
    assert_eq!(host_stream.recv_frame().await, Err(StreamError::Closed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_aborts_in_under_50_ms() {
    let relay = start(RelayConfig::default());
    let mut worst = Duration::ZERO;
    for round in 0..3 {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let session_id = waiting.session_id();
        let host_client = relay.client();
        let operator_client = relay.client();
        let registration = host_client.register_host(session_id).await.unwrap();
        let host_task = tokio::spawn(async move {
            let mut stream = registration.wait_for_operator().await.unwrap();
            host_handshake(waiting, &mut stream).await.map(|_| ())
        });
        let mut op_stream = operator_client.connect_operator(session_id).await.unwrap();
        let outcome = operator_handshake(&mut op_stream, session_id, "ZZZZZ-ZZZZZ").await;
        assert!(matches!(
            outcome.result,
            Err(HandshakeError::Rejected {
                remaining_attempts: 2
            })
        ));
        // El host no crea PendingLocalConsent: vuelve a WaitingForRequest con 1 fallo.
        let (_waiting, error) = host_task.await.unwrap().expect_err("sin consentimiento");
        assert_eq!(
            error,
            ConsentError::InvalidPassword {
                failed_attempts: 1,
                password_rotated: false
            }
        );
        eprintln!(
            "ronda {round}: aborto (confirmacion -> veredicto) = {:?}; handshake completo hasta el veredicto = {:?}",
            outcome.verdict_time, outcome.total_time
        );
        assert!(
            outcome.verdict_time < Duration::from_millis(50),
            "el aborto tardo {:?}",
            outcome.verdict_time
        );
        worst = worst.max(outcome.verdict_time);
    }
    eprintln!("peor aborto medido = {worst:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_wrong_passwords_rotate_then_the_new_one_connects() {
    let relay = start(RelayConfig::default());
    let host_client = relay.client();
    let operator_client = relay.client();
    let mut waiting = WaitingForRequest::start_client_reception().unwrap();
    let session_id = waiting.session_id();
    let old_password = waiting.display_password();

    for attempt in 1..=3u8 {
        let registration = host_client.register_host(session_id).await.unwrap();
        let host_task = tokio::spawn(async move {
            let mut stream = registration.wait_for_operator().await.unwrap();
            host_handshake(waiting, &mut stream).await
        });
        let mut op_stream = operator_client.connect_operator(session_id).await.unwrap();
        let outcome = operator_handshake(&mut op_stream, session_id, "ZZZZZ-ZZZZZ").await;
        assert!(outcome.result.is_err());
        let (back, error) = host_task.await.unwrap().expect_err("rechazado");
        assert_eq!(
            error,
            ConsentError::InvalidPassword {
                failed_attempts: attempt,
                password_rotated: attempt == 3
            }
        );
        waiting = back;
    }
    let new_password = waiting.display_password();
    assert_ne!(
        old_password, new_password,
        "la contrasena rota al tercer fallo"
    );

    // Cuarto lookup del minuto (dentro del cupo de 5): con la contrasena nueva conecta.
    let registration = host_client.register_host(session_id).await.unwrap();
    let host_task = tokio::spawn(async move {
        let mut stream = registration.wait_for_operator().await.unwrap();
        host_handshake(waiting, &mut stream)
            .await
            .map(|h| (stream, h.pending.sas()))
    });
    let mut op_stream = operator_client.connect_operator(session_id).await.unwrap();
    let outcome = operator_handshake(&mut op_stream, session_id, &new_password).await;
    let operator = outcome.result.expect("contrasena nueva valida");
    let (_host_stream, host_sas) = host_task.await.unwrap().expect("host autenticado");
    assert_eq!(host_sas, operator.sas);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sixth_lookup_per_minute_from_one_ip_is_rejected() {
    let clock = FakeRelativeClock::default();
    let relay = start(RelayConfig {
        clock: RelayClock::manual(clock.clone()),
        ..RelayConfig::default()
    });
    let client = relay.client();
    let unknown = sid("123-456-789");
    for attempt in 1..=5 {
        match client.connect_operator(unknown).await {
            Err(ClientError::Relay(RelayError::NotFound)) => {}
            other => panic!("intento {attempt}: esperaba NotFound, llego {other:?}"),
        }
    }
    assert!(
        matches!(
            client.connect_operator(unknown).await,
            Err(ClientError::Relay(RelayError::RateLimited))
        ),
        "el sexto intento del minuto debe rechazarse"
    );
    assert!(matches!(
        client.connect_operator(unknown).await,
        Err(ClientError::Relay(RelayError::RateLimited))
    ));

    // El registro de hosts tiene su propio limite: un host legitimo no queda bloqueado por el de Lookup.
    let registration = client.register_host(sid("222-333-444")).await;
    assert!(
        registration.is_ok(),
        "el registro no comparte cupo con Lookup"
    );

    // Con el tiempo se recupera una celda (5 por minuto = una cada 12 s).
    clock.advance(Duration::from_secs(12));
    assert!(matches!(
        client.connect_operator(unknown).await,
        Err(ClientError::Relay(RelayError::NotFound))
    ));
    assert!(matches!(
        client.connect_operator(unknown).await,
        Err(ClientError::Relay(RelayError::RateLimited))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_has_its_own_per_ip_limit() {
    let relay = start(RelayConfig {
        register_attempts_per_minute: std::num::NonZeroU32::new(3).unwrap(),
        clock: RelayClock::manual(FakeRelativeClock::default()),
        ..RelayConfig::default()
    });
    let client = relay.client();
    let mut held = Vec::new();
    for n in 0..3u32 {
        held.push(
            client
                .register_host(sid(&format!("100-000-{:03}", 100 + n)))
                .await
                .expect("dentro del cupo"),
        );
    }
    assert!(matches!(
        client.register_host(sid("100-000-999")).await,
        Err(ClientError::Relay(RelayError::RateLimited))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unpaired_slots_expire_and_the_host_is_told() {
    let relay = start(RelayConfig {
        slot_ttl: Duration::from_millis(300),
        sweep_interval: Duration::from_millis(50),
        ..RelayConfig::default()
    });
    let client = relay.client();
    let id = sid("555-666-777");
    let registration = client.register_host(id).await.unwrap();
    assert_eq!(relay.handle.waiting_slots(), 1);
    let waited = tokio::time::timeout(Duration::from_secs(5), registration.wait_for_operator())
        .await
        .expect("la limpieza avisa al host");
    assert!(matches!(
        waited,
        Err(ClientError::Relay(RelayError::Expired))
    ));
    assert_eq!(
        relay.handle.waiting_slots(),
        0,
        "la limpieza libero el slot"
    );
    assert!(matches!(
        client.connect_operator(id).await,
        Err(ClientError::Relay(RelayError::NotFound))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_slot_is_refused_even_before_the_sweeper_runs() {
    let relay = start(RelayConfig {
        slot_ttl: Duration::from_millis(150),
        sweep_interval: Duration::from_secs(3600),
        ..RelayConfig::default()
    });
    let client = relay.client();
    let id = sid("555-666-778");
    let registration = client.register_host(id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(matches!(
        client.connect_operator(id).await,
        Err(ClientError::Relay(RelayError::NotFound))
    ));
    let waited = tokio::time::timeout(Duration::from_secs(5), registration.wait_for_operator())
        .await
        .expect("el host se entera");
    assert!(matches!(
        waited,
        Err(ClientError::Relay(RelayError::Expired))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_id_is_rejected_and_slots_are_single_use() {
    let relay = start(RelayConfig::default());
    let id = sid("314-159-265");
    let first = relay.client();
    let registration = first.register_host(id).await.unwrap();
    let second = relay.client();
    assert!(matches!(
        second.register_host(id).await,
        Err(ClientError::Relay(RelayError::SessionIdTaken))
    ));

    let host_task = tokio::spawn(async move { registration.wait_for_operator().await });
    let operator = relay.client();
    let _op_stream = operator
        .connect_operator(id)
        .await
        .expect("empareja con el primero");
    let _host_stream = host_task.await.unwrap().expect("host emparejado");
    assert!(
        matches!(
            operator.connect_operator(id).await,
            Err(ClientError::Relay(RelayError::NotFound))
        ),
        "el slot se consume al emparejar"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_disconnect_frees_the_slot() {
    let relay = start(RelayConfig::default());
    let id = sid("271-828-182");
    {
        let client = relay.client();
        let registration = client.register_host(id).await.unwrap();
        assert_eq!(relay.handle.waiting_slots(), 1);
        drop(registration);
        client.close();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while relay.handle.waiting_slots() != 0 {
        assert!(Instant::now() < deadline, "el slot no se libero");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    relay
        .client()
        .register_host(id)
        .await
        .expect("el ID se puede registrar de nuevo");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_rejects_any_certificate_other_than_the_pinned_one() {
    let relay = start(RelayConfig::default());
    let impostor = RelayIdentity::generate().unwrap().pin();
    let client = RelayClient::new(relay.addr, impostor).unwrap();
    assert!(matches!(
        client.register_host(sid("123-123-123")).await,
        Err(ClientError::Connect(_))
    ));
    assert_eq!(relay.handle.waiting_slots(), 0);
}

/// Empareja un host y un operador sin handshake. Devuelve los clientes (mantienen vivos sus
/// endpoints) y los canales del host y del operador.
async fn pair(
    relay: &TestRelay,
    id: &str,
) -> (RelayClient, RelayClient, RelayedStream, RelayedStream) {
    let host_client = relay.client();
    let operator_client = relay.client();
    let registration = host_client.register_host(sid(id)).await.expect("registro");
    let host_task = tokio::spawn(registration.wait_for_operator());
    let operator = operator_client
        .connect_operator(sid(id))
        .await
        .expect("lookup");
    let host = host_task.await.unwrap().expect("emparejado");
    (host_client, operator_client, host, operator)
}

/// Bytes deterministas y variados para comparar de punta a punta.
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[1] ^ seed)
        .collect()
}

async fn read_to_end(stream: &mut VideoReceiver) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while let Some(n) = stream.read(&mut buf).await? {
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn tapped_len(captured: &Captured, direction: BridgeDirection) -> usize {
    captured
        .lock()
        .unwrap()
        .iter()
        .filter(|(dir, _)| *dir == direction)
        .map(|(_, bytes)| bytes.len())
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn video_streams_cross_the_relay_byte_exact_and_opaque() {
    let captured: Captured = Arc::default();
    let sink = captured.clone();
    let tap: ByteTap = Arc::new(move |dir, bytes| {
        sink.lock().unwrap().push((dir, bytes.to_vec()));
    });
    let relay = start(RelayConfig {
        tap: Some(tap),
        ..RelayConfig::default()
    });
    let (_hc, _oc, mut host, mut operator) = pair(&relay, "246-813-579").await;

    // Contenido que el relay interpretaria si lo parseara: una peticion de senalizacion, un error
    // del relay y un prefijo de longitud invalido. Debe llegar tal cual.
    let mut signaling = encode_frame(
        &encode_message(&ClientRequest::Lookup {
            session_id: 246_813_579,
        })
        .unwrap(),
    )
    .unwrap();
    signaling.extend(
        encode_frame(&encode_message(&RelayResponse::Error(RelayError::NotFound)).unwrap())
            .unwrap(),
    );
    let mut bad_length = vec![0xFF; 4];
    bad_length.extend(pattern(3, 1000));
    let payloads = vec![
        pattern(1, 512 * 1024),
        signaling,
        bad_length,
        vec![0x42],
        pattern(5, 200 * 1024),
    ];

    let host_video = host.video_streams();
    let mut writers = Vec::new();
    for payload in payloads.clone() {
        let video = host_video.clone();
        writers.push(tokio::spawn(async move {
            let mut stream = video.open().await.expect("abrir stream de video");
            stream.write_all(&payload).await.expect("escribir video");
            stream.finish().await;
        }));
    }
    let operator_video = operator.video_streams();
    let mut readers = Vec::new();
    for _ in 0..payloads.len() {
        let mut stream = operator_video.accept().await.expect("aceptar stream");
        readers.push(tokio::spawn(async move { read_to_end(&mut stream).await }));
    }
    let mut received = Vec::new();
    for reader in readers {
        received.push(reader.await.unwrap().expect("leer video"));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    let mut expected = payloads.clone();
    expected.sort();
    received.sort();
    assert_eq!(received, expected, "bytes identicos de punta a punta");

    // Simetrico: el operador tambien puede abrir un stream hacia el host.
    let back = pattern(9, 64 * 1024);
    let mut stream = operator_video.open().await.unwrap();
    stream.write_all(&back).await.unwrap();
    stream.finish().await;
    let mut incoming = host.video_streams().accept().await.unwrap();
    assert_eq!(read_to_end(&mut incoming).await.unwrap(), back);

    // El canal de control sigue funcionando junto a los streams de video.
    operator.send_frame(b"control").await.unwrap();
    assert_eq!(host.recv_frame().await.unwrap(), b"control");

    // El relay copio exactamente los bytes escritos: ni agrega ni quita nada (host -> operador solo
    // llevo video; operador -> host, el stream de vuelta y una trama de control).
    let video_total: usize = payloads.iter().map(Vec::len).sum();
    assert_eq!(
        tapped_len(&captured, BridgeDirection::HostToOperator),
        video_total
    );
    assert_eq!(
        tapped_len(&captured, BridgeDirection::OperatorToHost),
        back.len() + 4 + b"control".len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn video_streams_are_cut_when_an_end_drops() {
    let relay = start(RelayConfig::default());
    // Margen holgado: solo acota una espera que debe terminar; no mide tiempos.
    let limit = Duration::from_secs(30);

    // Cae el host: el operador ve fallar el stream de video, la aceptacion y el control.
    let (_hc, _oc, host, mut operator) = pair(&relay, "135-792-468").await;
    let mut sender = host.video_streams().open().await.unwrap();
    sender.write_all(&pattern(1, 1000)).await.unwrap();
    let operator_video = operator.video_streams();
    let mut receiver = operator_video.accept().await.unwrap();
    let mut first = vec![0u8; 1000];
    receiver.read_exact(&mut first).await.unwrap();
    assert_eq!(first, pattern(1, 1000));
    host.close();
    let read = tokio::time::timeout(limit, read_to_end(&mut receiver))
        .await
        .expect("el stream se corta");
    assert!(read.is_err(), "no debe parecer un final limpio: {read:?}");
    assert!(
        tokio::time::timeout(limit, operator_video.accept())
            .await
            .expect("la aceptacion termina")
            .is_err()
    );
    assert!(
        tokio::time::timeout(limit, operator.recv_frame())
            .await
            .expect("el control termina")
            .is_err()
    );

    // Cae el operador: el host deja de poder escribir video.
    let (_hc, _oc, host, operator) = pair(&relay, "135-792-469").await;
    let mut sender = host.video_streams().open().await.unwrap();
    sender.write_all(&pattern(2, 1000)).await.unwrap();
    let mut receiver = operator.video_streams().accept().await.unwrap();
    let mut first = vec![0u8; 1000];
    receiver.read_exact(&mut first).await.unwrap();
    operator.close();
    let chunk = pattern(3, 64 * 1024);
    let failed = tokio::time::timeout(limit, async {
        loop {
            if sender.write_all(&chunk).await.is_err() {
                break;
            }
        }
    })
    .await;
    assert!(failed.is_ok(), "la escritura de video debe fallar");
    // La escritura puede fallar por el STOP del relay antes de que llegue el cierre de la conexion;
    // se espera ese cierre (aceptar falla solo con la conexion cerrada) en vez de suponer el orden.
    assert!(
        tokio::time::timeout(limit, host.video_streams().accept())
            .await
            .expect("el relay cierra la conexion del host")
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn video_stream_limit_is_enforced() {
    let relay = start(RelayConfig::default());
    let (_hc, _oc, host, operator) = pair(&relay, "864-209-753").await;
    let host_video = host.video_streams();
    let operator_video = operator.video_streams();

    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for n in 0..MAX_VIDEO_STREAMS {
        let mut sender = host_video.open().await.expect("dentro del tope");
        sender.write_all(&[n as u8]).await.unwrap();
        senders.push(sender);
        let mut receiver = operator_video.accept().await.unwrap();
        let mut byte = [0u8; 1];
        receiver.read_exact(&mut byte).await.unwrap();
        receivers.push(receiver);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), host_video.open())
            .await
            .is_err(),
        "con {MAX_VIDEO_STREAMS} abiertos, el siguiente espera"
    );

    // Al cerrarse streams de punta a punta se liberan lugares (quinn devuelve el credito por lotes:
    // con un tope de 8, al liberarse 2).
    for n in 0..2 {
        senders[n].finish().await;
        assert_eq!(read_to_end(&mut receivers[n]).await.unwrap(), b"");
    }
    let mut extra = tokio::time::timeout(Duration::from_secs(30), host_video.open())
        .await
        .expect("se libero un lugar")
        .unwrap();
    extra.write_all(b"noveno").await.unwrap();
    extra.finish().await;
    let mut receiver = operator_video.accept().await.unwrap();
    assert_eq!(read_to_end(&mut receiver).await.unwrap(), b"noveno");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_operator_applies_backpressure_without_loss() {
    let relay = start(RelayConfig::default());
    let (_hc, _oc, host, operator) = pair(&relay, "975-310-864").await;
    // Mucho mayor que las ventanas de flujo en juego (unos 2,5 MB entre host, relay y operador).
    let payload = pattern(7, 8 * 1024 * 1024);
    let to_send = payload.clone();
    let host_video = host.video_streams();
    let writer = tokio::spawn(async move {
        let mut stream = host_video.open().await.unwrap();
        stream.write_all(&to_send).await.unwrap();
        stream.finish().await;
    });
    let mut receiver = operator.video_streams().accept().await.unwrap();
    let mut first = [0u8; 1];
    receiver.read_exact(&mut first).await.unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !writer.is_finished(),
        "si el operador no lee, el host queda frenado (el relay no acumula sin limite)"
    );

    let mut rest = read_to_end(&mut receiver).await.unwrap();
    rest.insert(0, first[0]);
    assert_eq!(rest, payload);
    tokio::time::timeout(Duration::from_secs(30), writer)
        .await
        .expect("el host termina al leer el operador")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_halves_read_and_write_at_the_same_time() {
    let relay = start(RelayConfig::default());
    let (_hc, _oc, host, operator) = pair(&relay, "112-358-132").await;
    const ROUNDS: usize = 200;

    let run_side = |stream: RelayedStream, mine: &'static str, theirs: &'static str| {
        let (mut sender, mut receiver) = stream.into_split();
        let writing = tokio::spawn(async move {
            for i in 0..ROUNDS {
                sender
                    .send_frame(format!("{mine}-{i}").as_bytes())
                    .await
                    .unwrap();
            }
            sender
        });
        let reading = tokio::spawn(async move {
            for i in 0..ROUNDS {
                let frame = receiver.recv_frame().await.unwrap();
                assert_eq!(frame, format!("{theirs}-{i}").into_bytes());
            }
        });
        (writing, reading)
    };
    let (host_writing, host_reading) = run_side(host, "host", "operador");
    let (op_writing, op_reading) = run_side(operator, "operador", "host");
    let limit = Duration::from_secs(10);
    for reading in [host_reading, op_reading] {
        tokio::time::timeout(limit, reading).await.unwrap().unwrap();
    }
    let _host_sender = host_writing.await.unwrap();
    let _op_sender = op_writing.await.unwrap();
}
