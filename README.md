# tRust-chat

A rust rewrite of my network security E2EE relay-client chat app project, featuring robust concurrency, type safety, and (probably) better cryptography. It _should_ be more performant than the Python version. I have tried to write everything as much as possible in Rust as a way to force me to learn the language and its idiosyncracies.

## Background + how to run this

The application assumes, for better or for worse, that each host knows the public key of every other host. But each host must know only their own private key. Maybe I will implement some kind of more sophisticated PKI to simplify this in the future, but that's what you're stuck with for now. Also, it is assumed that the relay can read the metadata behind every message to make routing easier. The metadata usually just consists of the sender and recipient usernames, along with replay/tamper protection nonces.

You'll need a rust runtime (duh) to run all the code. I recommend using `rustup` for this.


1. Generate keys

    All the messages for this app are required to be encrypted. Every user/host needs a pair of long-term cryptographic keys for this. Do not worry for I wrote a key generator utility to handle this. You must run this before running the relay server or client(s). `<your username>` refers to, you guessed it, your username.
    ```bash
    cargo run --bin keygen alice    # generate keys for user alice, if desired
    cargo run --bin keygen bob      # generate keys for user bob, if desired
    cargo run --bin keygen <your username> # generate keys for user <your username>, if desired
    ```
    > This creates the `keys/` subdirectory within the project, containing the private and public key-pairs for each user you specified. I promise each host reads only their own private key from this directory, along with the public keys for everyone else.

2. Start the relay

    The Relay is the central server. It routes encrypted packets between users but **cannot** read them (because they are unfortunately encrypted). Run this in a terminal window.

    ```bash
    cargo run --bin relay
    ```
    > You should see it listening on `127.0.0.1:8080`.

3. Start the clients

    Open two more terminal windows on your machine. You supply the username of each of your clients through command-line args.

    Window #1
    ```bash
    cargo run --bin client -- <username 1>
    # cargo run --bin client -- alice
    ```

    Window #2
    ```bash
    cargo run --bin client -- <username 2>
    # cargo run --bin client -- bob
    ```
    > Both clients will automatically load their keys from disk, connect to the relay, and register their presence.

4. Start yapping

    To start talking, a user must initiate a secure session (perform a handshake) with their desired recipient.

    If you are `alice` and did step 3 successfully, you'd probably want to type

    ```bash
    connect bob
    ```

    ...in case you wanna talk to bob. Otherwise, type in `connect <username of the client you want to talk to>`.
    > Hopefully, they are already connected and registered with the relay. Otherwise, you'll get an error.

    You will see logs scrolling as they perform an authenticated Diffie-Hellman key exchange. Once you see "Secure session established," the tunnel is open and you can start conversing!

    ```bash
    > hewwo bob :3
    ```
    bob should receive this message on the other end.

5. Close chat

    If you end your session as a client, type this in.

    ```bash
    exit chat
    ```

    The relay can be stopped with `Ctrl+C`.

## Tech stack

* I chose Rust cuz I've heard it's cool I guess. On a slightly more serious note, I wanted to learn how to write memory-safe and concurrent programs in it.
* I used `tokio` for its asynchronous handling of TCP networking, non-blocking I/O, and managing concurrent tasks. This is different from the way my team implemented the project in Python before, because that involved explicit multithreading and blocking I/O with some degree of busywaiting. This makes the Rust implementation much more performant I hope.
* `x25519-dalek` implements elliptic curve Diffie-Hellman for key exchange and to establish shared secrets.
* `ed25519-dalek` implements Edwards-curve Digital Signature Algorithm (provides authentication).
* `chacha20poly1305` implements the ChaCha20 stream cipher with Poly1305 MAC (AEAD) for symmetric encryption of the chat messages.
* `rand` for secure random ephemeral key and nonce generation
* `zeroize` ensures sensitive memory (like private keys) is securely cleared/overwritten when dropped to prevent memory dump attacks.
* `serde` for serializing and deserializing Rust data structures efficiently.
* `bincode` to encode packets for network transmission. It is smaller and faster than JSON I believe.
* `hex` to encode keys into readable strings for storage

## Security assurances

Any (ostensibly) encrypted chat app worth its salt must bring something to the table, right?

- [x] Confidentiality: Messages in a secure tunnel are encrypted using `ChaCha20-Poly1305` using a shared session key. Only the intended recipient holding the matching session key can decrypt its contents.
- [x] Data Integrity: The `Poly1305` authenticator (part of the AEAD cipher) ensures that if a message is tampered with in transit (by the Relay or a MITM), decryption will fail, and the packet will be rejected.
- [x] Authentication & Non-Repudiation: Every packet is signed with the sender's Ed25519 private key. The recipient verifies this signature against the sender's public key (stored on disk), guaranteeing the message actually came from the claimed user.
- [x] Forward Secrecy: The session key is derived from an Ephemeral Diffie-Hellman exchange (`Handshake::new()` generates a random secret every time). If a user's long-term identity key is stolen in the future, the attacker cannot decrypt past conversations because the ephemeral session keys were never stored and cannot be recreated.
- [x] Man-in-the-Middle Protection: The client verifies the signature of the Handshake packet. If an attacker tries to inject their own public key during the handshake, the signature verification will fail (assuming the users have already exchanged trusted public keys via the keys/ directory).
- [ ] Replay Protection: Currently, the Rust client does not implement sequence numbers or timestamps (unlike the Python prototype which checked timestamps). A "Replay Protection" mechanism is required to prevent an attacker from capturing a valid encrypted packet and re-sending it later to confuse the client.
- [ ] Perfect Forward Secrecy (Per-Message): This would advance the encryption key with every single message, ensuring that even if a session key is compromised mid-chat, previous messages in that same session remain secure.
- [ ] Some form of PKI (stretch goal)
