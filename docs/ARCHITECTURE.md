# Arquitetura — Provenance Gate

## Componentes

| Componente | Responsabilidade | Limite de confiança |
|---|---|---|
| `src/cli.js` | Interface, validação de opções e códigos de saída fail-closed | Nunca imprime PEM, arquivos brutos ou exceções de entrada |
| `src/io.js` | Abertura de arquivos regulares, limites e hash em streaming | Artefatos e atestações são entradas não confiáveis |
| `src/strict-json.js` | JSON estrito, chaves duplicadas e propriedades perigosas recusadas | Não executa conteúdo |
| `src/index.js` | DSSE, Ed25519, PAE, política de confiança e subjects | Chaves confiáveis vêm somente de política separada |
| Política aprovada | Chaves públicas, quórum, repositório, commit, builder e buildType | Controlada independentemente do produtor do artefato |

## Emissão

1. Obter hashes SHA-256 dos artefatos.
2. Criar um in-toto Statement v1 com subject e predicado no formato SLSA Provenance v1.
3. Construir uma representação DSSE PAE do tipo e payload.
4. Assinar a PAE com Ed25519; a chave identificada é o SHA-256 do SPKI.
5. Coassinar com outras chaves privadas, sem substituir o payload original.

```text
Artefatos → SHA-256 → Statement in-toto → DSSE PAE → Ed25519 Sign A
                                                       ↓
                                            Ed25519 Sign B
                                                       ↓
                                              Envelope A+B
```

A proveniência é autodeclarada pelo signatário, não verificada contra infraestrutura externa de build.

## Verificação

```text
Política independente ──────┐
                            ├── chaves confiáveis + threshold M-de-N
Envelope DSSE ──────────────┤
                            ├── verificação criptográfica do payload
                            ├── repository/commit/builder/buildType exatos
Artefatos recebidos ────────┤
                            └── hashes SHA-256 + conjunto exato de nomes → PASS/FAIL
```

A ordem é **parse seguro → chaves/quórum → identidade declarada → hashes/nomes**. Nenhum artefato é executado.

## Formatos de dados

- Envelope DSSE: `payloadType`, `payload` (base64 canônico), `signatures[{keyid,sig}]`.
- Payload: in-toto `_type=https://in-toto.io/Statement/v1`, `subject[{name,digest:{sha256}}]`, `predicateType=https://slsa.dev/provenance/v1`.
- Proveniência: `buildDefinition` e `runDetails`, com repositório e commit declarados.
- Política: `schemaVersion=1`, `trustedKeys[{keyid,publicKeyPem}]`, `threshold`, `repository`, `commit`, `builder`, `buildType`.

Campos adicionais são recusados para manter o perfil restrito e revisável.

## Rotação e gestão de confiança

Gere nova política para cada commit aprovado e, quando necessário, novo conjunto de chaves/quórum. Políticas são dados publicáveis, mas exigem distribuição/autorização independente da release; arquivos PEM privados devem permanecer secretos e fora do Git.

## Referências

[DSSE](https://github.com/secure-systems-lab/dsse) · [in-toto](https://github.com/in-toto/attestation) · [SLSA](https://slsa.dev/spec/v1.2/provenance) · [Sigstore](https://docs.sigstore.dev/)
