
# Soft Seal

Soft Seal is a solution for protecting secrets at rest and only unlocking them when the application runs on an authorized machine. The word soft emphasizes that this is a purely software approach. No hardware modules, TPMs, HSMs, dongles, or cloud KMS services are required. Instead, "Soft Seal" derives encryption keys from machine-specific characteristics, combined with modern cryptographic primitives, so that secrets can be safely stored on disk or in a database without remaining readable if that storage is stolen.

## The Challenge: Safely Handling Secrets

Imagine that our program needs to access a secret. A secret is any value that must remain confidential but still needs to be read by software at runtime. Examples include:

- **Service Credentials**: API keys, OAuth client secrets
- **Access Tokens**: OAuth access tokens, bearer tokens
- **Encryption Keys**: AES keys, Fernet keys
- **Webhook Signing Keys**: Stripe, GitHub, etc.
- **Database Credentials**

We cannot hard-code secrets into source code, or store them in plaintext in configuration files, containers, or databases. If an attacker gains access to the source repository, container image, backup, or database, the secret should not be immediately exposed. To solve this, there are two broad families of solutions. Each solves different problems and offers different levels of protection.

- Code obfuscation
- Cryptographic secret storage

Let us go over each technique with more details.

### Code Obfuscation

The goal is to make secrets difficult to extract by reverse engineering, especially from compiled applications. Obfuscation tools transform code or string literals into forms that are harder to read, and harder to statically analyze. Typical techniques include:

- String obfuscation: Encode string constants at build time, and decode them only when needed at runtime.
- Control-flow obfuscation: Restructure code to look confusing to humans and decompilers.
- Packing or binary wrapping: Compress and wrap the program so tools like `strings` show nothing useful.

For compiled languages like C/C++, Rust or Golang, obfuscation works reasonably well. Strings can be transformed at compile time. Reverse engineers must analyze the binary or debug at runtime. For interpreted languages like Python or JavaScript, obfuscation is weaker. The runtime can often be inspected. Tools exist to "de-obfuscate" or step through execution.

Code obfuscation increases attacker effort and cost. It is useful when you must ship code to untrusted environments and prevents trivial leaks such as `strings binary | grep key`. However, obfuscation is not security, it is delay. It is appropriate when secrets must exist on client devices, but it cannot guarantee protection. If the program can read the secret locally, a skilled attacker can eventually read it too. A determined attacker can:

- attach a debugger,
- dump process memory,
- log the decrypted value,
- or hook the function that uses it.

**Example**

[obfusheader.h](https://github.com/ac3ss0r/obfusheader.h) is a header-only C++14 library that offers several obfuscation features at compile time, using template metaprogramming and macros. The example in [main.cpp](./obfuscation_c++/main.cpp) shows how the library transforms string literals, constants, and function calls so that they do not appear in plaintext in the compiled binary, while still being correctly reconstructed and executed at runtime.

    $ cd obfuscation_c++
    $ curl -L -o obfusheader.h https://raw.githubusercontent.com/ac3ss0r/obfusheader.h/refs/heads/main/include/obfusheader.h
    $ g++ -std=c++14 -O2 main.cpp -o demo
    $ ./demo

Sample output:

    char*: this is a secret literal
    int (dec): 123
    boolean: 1

    MAKEOBF decrypted: another secret

    [secret_function] calling hidden function

    Very secure call from printf

The example highlights three main obfuscation features: Obfuscating literals and constants (`OBF`), Safe wrapper (`MAKEOBF`), and function call hiding (`CALL`). Note that this demo is illustrating obfuscation techniques, not cryptographic secret storage. Obfuscation does not secure secrets in the cryptographic sense.

### Cryptographic Secret Storage

The goal is to prevent attackers from recovering secrets even if they fully understand the code and steal the storage. Instead of hiding the secret, we encrypt it using well-studied cryptographic techniques. If an attacker steals the database or config files, they get only ciphertext, not the secret. Common implementations include:

- Host-bound key derivation (e.g., using machine-specific identifiers)
- Hardware-backed key stores (TPM, Secure Enclave, HSMs)
- Cloud key management (AWS KMS, Azure Key Vault, GCP KMS)
- Dedicated secret managers (Vault, Kubernetes Secrets, etc.)

The "Soft Seal" project belongs to the host-bound secret storage. It raises the bar significantly for attackers who have access to storage while remaining lightweight, portable, and practical for environments where dedicated hardware security is unavailable or unnecessary.

## Designing a Host-bound Secret Storage

In the following sections, we will design a host-bound secret storage system step by step, exploring multiple approaches along the way. Each attempt intentionally builds on the previous one. Starting with naïve ideas, understanding why they fail, and then progressively improving the design. This progressive refinement approach is valuable not only because it leads us to a secure final solution, but also because it illustrates the trade-offs, pitfalls, and reasoning behind each decision.

### Attempt 1: Hashing

In the first idea, we take the secret, run it through a cryptographic hash function (such as SHA-256), and store the resulting hash in a file or database:

    secret  →  [Cryptographic Hash Function]  →  a94a8fe5ccb…  (stored)

A cryptographic hash is one-way. It is computationally infeasible to reconstruct the original value from the hash output. When the program later needs the secret, it can only read the stored hash. There is no way to "un-hash" it back into the original value.

This property makes hashing excellent for password verification. The system does not need to know the user’s password; It only needs to check that the password the user typed hashes to the same value as the one stored.

This approach fails for our use case. We need to recover the original secret so the program can use it. Because hashing is intentionally irreversible, a purely hash-based design cannot work for secret storage.

### Attempt 2: Naïve Encryption (Key Stored with the Data)

In the second approach, we generate a random symmetric encryption key, use it to encrypt the secret, and then store both the encrypted blob and the encryption key in the same file or database so the application can decrypt it later.

    secret  →  [Encrypt with Key K]  →  EncryptedBlob
    Stored: { key: K, blob: EncryptedBlob }

At first glance, this feels secure because the secret is no longer stored in plaintext. However, this design suffers from what is often called the "key under the doormat" problem. We locked the data, but we stored the key right next to it. If an attacker steals the database or configuration file, they obtain both the encrypted blob and the key, and can simply decrypt the secret offline.

The encryption itself may be strong, but the key management is fundamentally broken. Because the key and ciphertext live side-by-side, this approach provides almost no real protection and is not suitable for our scenario.

### Attempt 3: Host-Bound Key

Next, we move away from storing the encryption key at all. Instead, we let the application derive the key from properties of the machine it runs on such as a unique operating-system identifier.

    MachineID  →  Key Derivation Function  →  DerivedKey
    secret     →  Encrypt with DerivedKey  →  EncryptedBlob
    Stored in DB: EncryptedBlob

At runtime the program asks the OS for the Machine ID. It deterministically derives the same encryption key again, and decrypts the stored blob. Now we get an important property:

> The secret can be decrypted only on that machine.

If someone steals just the database, they cannot reconstruct the key because it was never stored anywhere. This is now much closer to what we want, but there is still a problem. If two machines have the same or predictable Machine ID, they would generate the same encryption key. And attackers can even pre-compute likely keys ahead of time. To fix that, we need salt.

### Attempt 4: Host-Bound Key with Salt

In this refinement, we introduce `salt`. It is a random value generated once and stored alongside the encrypted blob.

    (MachineID + Salt)  →  Key Derivation Function  →  DerivedKey
    secret              →  Encrypt with DerivedKey  →  EncryptedBlob
    Stored in DB: { Salt, EncryptedBlob }

The program never stores the encryption key. Instead, it reconstructs it deterministically at startup:

- Read the Machine ID from the operating system.
- Read the Salt from storage.
- Run both through the key-derivation function.
- Use the resulting key to decrypt the encrypted blob.

Because the same inputs always produce the same output, the application can reliably regenerate the key — while an attacker who only has the database cannot.

Note that salt is not "optional hardening". It prevents an entire class of attacks. Imagine thousands of systems using the same technique without salt. Many machines, particularly cloud images and default installations, often share identical or predictable identifiers:

- User A (AWS): Machine ID = ip-172-31-0-1 → Derived key = ABC
- User B (AWS): Machine ID = ip-172-31-0-1 → Derived key = ABC

Without salt identical Machine IDs produce identical encryption keys. A motivated attacker could exploit this using a **rainbow table** attack. The attacker can build a table of pre-computed derived keys for the most common machine identifiers (e.g., localhost, raspberrypi, common EC2 hostnames, etc.) and then try each pre-computed key against your encrypted blob. If your machine happens to use one of those common identifiers, the attacker decrypts your secrets instantly.

## Implementation

Now that we have the design (a host-bound key derived from Machine ID + Salt) we can describe how it is implemented in practice. We never store an encryption key directly. Instead, we teach the program how to rebuild the key every time it runs, using inputs that are specific to the host. The inputs are:

- **Machine ID**: a stable identifier provided by the OS.
- **Salt**: a cryptographically random byte string generated once and stored alongside the encrypted blob.

We feed MachineID and Salt into a key-derivation function such as `PBKDF2-HMAC-SHA256`. It iterates the underlying hash function a large number of times, which strengthens weak or predictable inputs, and slows down brute-force and rainbow table attacks. PBKDF2 produces a fixed-length binary string. We then Base64-url encode this value to obtain a Fernet-compatible key string.

```text
  [ MACHINE ID ]             [ SALT ]
        |                       |
        +-----------+-----------+
                    |
                    v
        [ PBKDF2HMAC "The Mixer" ] <--- (Loops 100,000 times)
                    |
                    |  <-- Output: 32 Bytes of Raw Binary (Gibberish)
                    v
           [ Base64 Encoder ]  <--- (The Translator)
                    |
                    |  <-- Output: 44 Char String (Safe Text)
                    v
        +-----------------------+
        | DERIVED ENCRYPTION KEY|  <-- READY FOR FERNET
        +-----------------------+
```

The important property is that this process is deterministic. The same Machine ID + Salt + parameters will always produce the same derived key, but we never need to store the key itself.

The derived encryption key from PBKDF2 becomes the Fernet key. Instead of directly using AES and HMAC ourselves (which is easy to misuse), Fernet wraps these low-level primitives in a safe, standard format. It typically provides:

- Confidentiality: AES-128 in CBC mode.
- Integrity & authenticity: HMAC-SHA256 over the ciphertext + metadata.
- Optional timestamp: So you can enforce a max age if you want.

The result is a URL-safe, opaque token that we can store on disk or a database.

```text
   +------------------------+                +-----------------------+
   | DERIVED ENCRYPTION KEY |                |        Secret         |
   +------------------------+                +-----------------------+
               |                                        |
               v                                        v
      +----------------------------------------------------------+
      |                  FERNET ENCRYPTION ENGINE                |
      |                                                          |
      |   1. Initialize Engine with 'derived encryption key'     |
      |      fernet = Fernet(key)                                |
      |                                                          |
      |   2. Encrypt 'secret'                                    |
      |      token = fernet.encrypt(secret)                      |
      |                                                          |
      |   3. (Internal Magic: AES-128 + HMAC + Timestamping)     |
      +----------------------------------------------------------+
                                   |
                                   v
                         +-------------------+
                         |  ENCRYPTED BLOB   |
                         +-------------------+
                                   |
                                   v
                           [ SAVE TO Store ]
```

If an attacker steals only the database, they obtain the salt, and the encrypted blob, but not the Machine ID. Without that missing input, they cannot reconstruct the derived key and cannot decrypt the secret. However, if an attacker gets access to your server:

- They can read the Machine ID.
- They can read the salt from the DB.
- They can run PBKDF2 and derive the key.
- They can decrypt the blob.

So this is not a replacement for:

- Hardware Security Modules (HSMs)
- KMS services (AWS KMS, GCP KMS, HashiCorp Vault)
- Proper OS hardening and access control

You should also understand the portability consequence. If you move the DB to another machine, you cannot decrypt the secrets there (by design). You’d need a migration process that re-encrypts them with the new machine’s key.

## Machine ID

We need to bind secrets to a specific host without requiring specialized hardware. Linux’s `/etc/machine-id` is a strong candidate for this purpose. The value in `/etc/machine-id` is generated when the OS is installed and has the following properties:

- Unique to that OS instance
- Persistent across reboots
- Stable unless the system is re-imaged
- Stored on disk
- Widely used by core services (systemd, D-Bus, journald, snapd, etc.)

Here is an example:

    $ cat /etc/machine-id
    c00e367c44774a2ca96a00b1b99edddc

If `/etc/machine-id` is not available, a safe fallback is to generate a random 32-byte identifier and store it in a root-restricted file that we can reuse later. This preserves host binding without weakening security. Do not use a fixed default value. Also avoid combining the hostname with machine-id. If the hostname changes, all previously encrypted blobs become unreadable.

### Machine ID in Containers

Minimal Ubuntu / Debian Docker images often ship with either no `/etc/machine-id`, or an empty file. This is intentional so that images can be cloned freely, and no two containers accidentally share the same machine-id.

    $ docker run -it --name ubuntu-lts ubuntu:latest bash
    # cat /etc/machine-id
    # <empty>

If the goal is to keep data tied to the host OS, then you can mount the host’s machine-id into the container:

    $ docker run -it --name ubuntu-lts -v /etc/machine-id:/etc/machine-id:ro ubuntu:latest bash
    # cat /etc/machine-id
    # c00e367c44774a2ca96a00b1b99edddc

This ensures our soft-seal behaves as if it were running directly on the host, and container rebuilds or restarts will not change the identity. If container-level binding is acceptable, use the fallback mechanism. Generate a random ID, store it in an application-owned path, and persist it using a Docker volume.

> Avoid generating machine-id at image build time. All containers created from that image would inherit the same ID, which breaks uniqueness and weakens security. Instead, generate the fallback at runtime and persist it.

## Getting Started

Build the docker image:

    docker compose build

Start the container:

    docker compose up -d

Open an interactive shell to the container:

    docker exec -it soft_seal bash

The `seal.py` serves two roles:

- CLI
- Library

To use the CLI functionality, invoke the script with `init` command:

    python3 seal.py init

It will ask for the secret:

    Enter secret to seal:
    Confirm secret:

And you should get the following message if everything goes well:

    Secret sealed and stored successfully.

This indicates that the salt and encrypted blob were saved into Redis DB.

To restore your secret, simply invoke:

    python3 seal.py show

You original secret will be printed:

    Restored secret:
    xxxxx

If you run `init` again fro the second time, you will get an error:

    python3 seal.py init
    A secret is already stored in Redis. Use --force to overwrite.

This means that a secret already exist in the database. You can use `--force` to replace the existing one:

    python3 seal.py init --force

Your real apps (FastAPI, Flask, whatever) would do exactly what [app.py](./app.py) does.
