# Provenance Gate

**Controle criptográfico de admissão de releases com DSSE, Ed25519, atestações in-toto, políticas de proveniência e quórum de assinaturas.**

> **Estado: v0.1.0 — projeto educacional/experimental de segurança da cadeia de suprimentos de software.** Sem auditoria independente. O uso do formato SLSA Provenance v1 **não significa** SLSA Level 1/2/3/4, proveniência de build validada externamente ou atestação keyless.

## O problema

Um arquivo pode ser trocado após o build, uma assinatura pode ser emitida por uma chave desconhecida ou o consumidor pode aceitar uma declaração associada ao repositório, commit ou executor incorreto. Verificar apenas um hash copiado do mesmo lugar que o download não estabelece uma raiz de confiança.

O **Provenance Gate** permite **bloquear a distribuição** até que os bytes dos artefatos correspondam ao conteúdo de uma declaração assinada por um número configurável de signatários aprovados, e que a identidade da origem e do processo declarados coincidam com uma política independente.

Esta solução é **diferente** de scanners de dependências, FIM, detectores de segredos, validadores de configuração e geradores de SBOM: o foco é a **autenticidade criptográfica de uma declaração de procedência e dos bytes distribuídos**.

## Funcionalidades de destaque

| Controle | Implementação |
|---|---|
| Envelope **DSSE** | PAE conforme especificação, com payload e tipo assinados |
| Assinatura **Ed25519** | Primitivas criptográficas nativas do Node.js |
| Declaração de proveniência | **in-toto Statement v1**, perfil de **SLSA Provenance v1** |
| Assinaturas múltiplas | **M-de-N** chaves públicas distintas, configuráveis |
| Trust root externo | Chaves não são aceitas como confiáveis por estarem no envelope |
| Identidade rigorosa | Repository HTTPS, SHA Git completo, builder e buildType com igualdade exata |
| Artefatos reais | SHA-256 em streaming + conferência do **conjunto exato** de nomes e hashes |
| Entrada maliciosa | JSON estrito com rejeição de chaves duplicadas, base64 não canônico e limites |
| Proteções de arquivos | Rejeição de links simbólicos, abertura com `O_NOFOLLOW` quando suportado |
| Privacidade | Sem imprimir chave privada, payloads ou mensagens internas de erro |
| CI/CD | Exit 0 aprovado, 1 política/integridade rejeitada, 2 operação inválida/incompleta |
| Segurança de dependências | **Zero dependências de runtime** externas; biblioteca padrão Node.js |
| Compatibilidade planejada | Node 22/24, Ubuntu, Windows, macOS |

## Arquitetura simplificada

```text
                       BUILD / ARTIFACT
                             |
                          SHA-256
                             |
          in-toto Statement v1 + SLSA provenance claim
                             |
                    DSSE PAE + Ed25519
                             |
                      Signer A + B
                             |
                     DSSE envelope
                             |
                  VERIFIER / RELEASE GATE
                 /                       \
    Política externa confiável      Artefatos recebidos
     KeyID / quórum 2-de-2          SHA-256 e nomes
     commit / repository                 |
     builder / buildType                 |
                 \                       /
                  +--- todas as regras --+
                          |       |
                         PASS    FAIL
```

## Requisitos

Node.js **22 ou 24**, npm para testes e empacotamento; execução **offline** e sem banco de dados. Não precisa instalar bibliotecas adicionais de produção nem consultar APIs externas. O demo usa exclusivamente material descartável.

```bash
npm ci --ignore-scripts
npm run check
npm test
npm run demo
```

Também é possível executar a CLI diretamente, sem instalar dependências:

```bash
node src/cli.js --help
```

## Comandos

| Comando | Função |
|---|---|
| `keygen` | Gerar par Ed25519; segredo local protegido e chave pública separada |
| `attest` | Hash de artefatos + declaração in-toto/SLSA em envelope DSSE assinado |
| `cosign` | Acrescentar assinatura independente ao mesmo payload, sem reescrevê-lo |
| `policy-create` | Criar política de confiança independente, identidade e quórum M-de-N |
| `verify` | Verificar assinaturas, política completa e bytes de **todos** os arquivos |

### Demo completa, com adulteração detectada

```bash
npm run demo
```

Saída esperada:

```text
PASS — 2/2 trusted Ed25519 signers, pinned source identity and artifact SHA-256 verified.
PASS — altered release bytes rejected, no approval issued.
Demo credentials were temporary and have been discarded.
```

O tutorial detalhado para assinatura, coassinatura e validação via CLI está em **[docs/DEMO.md](docs/DEMO.md)**.

## Uso automatizado em CI

Em uma etapa separada da assinatura, após compilar os artefatos e disponibilizar um envelope verificado por canal confiável:

```bash
node src/cli.js verify \
  --attestation dist/release.intoto.json \
  --policy trust/release-policy.json \
  --artifact dist/app.tar.gz \
  --json
```

**Bloqueie a publicação se o processo retornar 1 ou 2.** A política deve ser versionada e protegida em fluxo independente do artefato: aceitar a política enviada pelo mesmo agente não confiável eliminaria o benefício do trust root.

## Códigos de saída

- **0 — PASS:** validação concluída com todas as exigências satisfeitas ou comando administrativo concluído.
- **1 — FAIL:** número de assinaturas confiáveis insuficiente, identidade da origem divergente ou hash/conjunto de artefatos diferente.
- **2 — ERROR:** falha de I/O, input malformado, configuração inválida ou verificação incompleta. **Não significa aprovação.**

## Limites operacionais

Limites padrão e máximos fixos: **100 artefatos**, **512 MiB por artefato**, **1 GiB de artefatos no total**, envelope de **1 MiB**, política de **64 KiB**, **20 assinaturas** e profundidade de **32** níveis JSON. As chaves privadas devem estar com permissão 0600 em Unix. São rejeitados links simbólicos para os arquivos finais; condições de corrida em diretórios ancestrais ainda são um risco documentado.

## Garantias vs. limitações

- **Comprova:** uma ou mais chaves privadas correspondentes às chaves públicas aprovadas assinaram os **bytes exatos** do payload DSSE, que declara os hashes dos artefatos. A comparação local confirma os bytes recebidos.
- **Não comprova:** que a afirmação de origem/commit/builder é verdadeira no mundo externo, que um GitHub Actions específico executou o build, que a compilação foi reproduzível ou que há conformidade SLSA certificada.
- **Não substitui:** Sigstore, Rekor, Fulcio, GitHub Artifact Attestations, TUF, SLSA Verifier, auditoria de dependências ou scanners de código.
- **Sem verificação temporal confiável:** use uma nova política fixada no commit de cada release; não há sistema de carimbo de tempo independente.

Para esse tipo de garantia remota, complemente com as implementações oficiais de **GitHub Artifact Attestations** ou **Sigstore**.

## Qualidade e segurança

O workflow `.github/workflows/ci.yml` executa **Node.js 22 e 24** em **Ubuntu, Windows e macOS**, com análise sintática, testes de regressão criptográficos e adversariais, empacotamento e auditoria npm. A aprovação local não deve ser confundida com o resultado futuro do GitHub Actions até que o repositório esteja publicado e o workflow seja executado.

| Documentação | Conteúdo |
|---|---|
| [SECURITY.md](SECURITY.md) | Política de divulgação, raiz de confiança, ameaças e limites |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modelo de dados, fluxo de assinatura e verificação |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Matriz de ameaças, controles e riscos residuais |
| [docs/DEMO.md](docs/DEMO.md) | Tutorial detalhado, assinatura, coassinatura e manipulação detectada |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Regras de contribuição e revisão |
| [CHANGELOG.md](CHANGELOG.md) | Evolução de versões |

## Referências técnicas

- [DSSE: Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [in-toto Attestation](https://github.com/in-toto/attestation)
- [SLSA Build Provenance](https://slsa.dev/spec/v1.2/provenance)
- [Sigstore](https://docs.sigstore.dev/)
- [OpenSSF](https://openssf.org/projects/)

## Licença e autoria

**MIT License**, © 2026 **Felipe Watter**. Projeto original para demonstração e pesquisa defensiva de segurança de cadeia de suprimentos; sem dependências de runtime externas.