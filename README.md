# Permissionless OpenAI API Access

## TL;DR
In this project, I integrate **TLS Notary** into the **AWS Nitro Enclave** and enhance the **Nitro remote attestation process** to provide additional guarantees for all parties involved.

I modify the attestation document to include:
- **Nonce**: Ensures the attestation document is generated in response to a specific request, preventing replay attacks.
- **Certificate Fingerprint**: Confirms that the TLS session terminates inside the enclave.

While functional, **TLS Notary** introduces significant delays — up to two minutes per request — resulting in potential OpenAI timeouts.

## Secondary Markets
> *Note: This is a research project, not intended for production use and I do not claim any novelty over this ideas. My Rust skills are very rusty.*

This project demonstrates how **Multiparty Computation (MPC)** and **Trusted Execution Environments (TEE)** can be combined to enable secondary markets for stateless transactional enterprise APIs, such as the **OpenAI LLM completion API**.

The goal is to maintain **authenticity guarantees**, even if the TEE is compromised, by introducing MPC. For simplicity, the example focuses on the OpenAI completion API, but the approach could be applied to other transactional APIs.

## Guarantees
**Miners** operate TEE-based nodes called **TEEProxy**.  
**Service Providers** provide valid OpenAI API keys to these nodes, with the assurance that miners cannot view the keys.  
**Users** interact with TEEProxy nodes and receive the following guarantees:

- **Authenticity**: Responses are genuinely from the OpenAI API and unaltered.
- **Privacy**: Miners and Service Providers cannot see user queries.
- **Censorship Resistance**: OpenAI cannot block users from accessing the API.
- **Pseudonymity**: OpenAI cannot trace requests back to individual users.

## Enclave App Fingerprinting
TEEProxy must be built from publicly available source code using a reproducible build process. In AWS Nitro, the entire enclave is encapsulated in a `.eif` binary file, with specific **Platform Configuration Registers (PCRs)** for fingerprinting:

- **PCR0**: Hash of the entire `.eif` file.
- **PCR1**: Hash of the Linux kernel and bootstrap code.
- **PCR2**: Hash of the application (from the Docker image).

Upon launch, Nitro recalculates the PCR values and includes them in the attestation document, which is signed by AWS private key.

## Miners and Service Providers
To ensure miners cannot access the OpenAI API keys, **AWS Nitro's remote attestation** is used to generate an attestation document. This document contains PCR values that reflect the exact software build running inside the enclave and is signed by AWS to verify its origin. 

However, by default, there's no mechanism to guarantee that the attestation document was created in response to the current Service Provider’s request, leaving a potential attack surface. To mitigate this, I added an endpoint `/enclave/attestate?nonce=beef...`, where the Service Provider includes a random nonce in each request. This nonce is then incorporated into the attestation document, ensuring the document is freshly generated.

Next, I address another issue: ensuring that the **TLS session terminates inside the enclave**. TEEProxy obtains a certificate from **Let's Encrypt** (via the ACME challenge) and adds the **certificate fingerprint** to the attestation document. This guarantees that the TLS session is securely terminated inside the enclave.

### Attestation Process Summary:
1. Call `/enclave/attestate?nonce=dead...` to retrieve the attestation document.
2. Verify the document is signed by AWS.
3. Confirm the document contains the correct nonce.
4. Check that the document contains the correct TLS certificate fingerprint.

Following this process ensures that API requests are securely terminated within the enclave. After this, the Service Provider can call `/enclave/provision?openai_key=docdoc...` to securely provide the OpenAI API key.

## Users and Miners
The same remote attestation process that ensures privacy for Service Providers extends to users, providing them with:

- **Privacy**: The attestation process guarantees that miners cannot view their queries.
- **Censorship Resistance**: Decentralized miners ensure no single entity (including OpenAI) can block access.
- **Pseudonymity**: The diversity of Service Providers prevents OpenAI from linking user requests.
- **Authenticity**: The **MPC** and **TLS Notary** within the enclave ensure the integrity of the responses. Sensitive data like cookies and keys are redacted as part of the standard functionality of TLS Notary.

## Conclusion
By integrating **TLS Notary** with **AWS Nitro TEE**, I enhance the remote attestation process to provide stronger guarantees for all involved parties. The attestation document is augmented to include:
- **Nonce**: Ensures the attestation document is generated for the current request.
- **Certificate Fingerprint**: Guarantees that the TLS session terminates inside the enclave.

However, TLS Notary introduces substantial delays (up to two minutes per request), leading to possible OpenAI timeouts. A potential improvement could be OpenAI including a hash of the response in each request, reducing the amount of data that needs to be verified by the TLS Notary.
