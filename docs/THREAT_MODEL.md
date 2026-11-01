# Modelo de ameaças — Provenance Gate v0.1.0

## Objetivo

Recusar a distribuição de artefatos sem uma declaração assinada pelo quórum de chaves previamente autorizadas que vincule os bytes recebidos às identidades de repositório, commit, builder e tipo de build estabelecidas na política externa.

## Ativos e limites de confiança

- **Chaves privadas Ed25519:** somente os signatários autorizados podem acessá-las.
- **Política externa:** lista confiável de chaves públicas, quórum, commit, repositório e builder.
- **Artefatos:** arquivos apresentados ao gate, não considerados confiáveis antes da verificação.
- **Atestação DSSE:** declaração assinada, mas não fonte autossuficiente de confiança.
- **Ambiente de build:** pode ser comprometido; esta CLI não verifica sua autenticidade independentemente.

## Matriz de ameaças

| Ameaça | Proteção | Risco residual |
|---|---|---|
| Alteração de arquivo após a assinatura | Hash SHA-256 comparado aos bytes entregues | Comprometimento da chave/política |
| Substituição de signatário | Ed25519 + chaves fixadas na política | Roubo de chave privada |
| Comprometimento de uma única chave | Quórum de chaves distintas | Chaves podem estar sob o mesmo controlador humano |
| Troca de repositório/commit/builder | Comparação exata com política | Signatário pode mentir sobre a origem externa |
| Arquivo não listado na declaração | Conjunto exato de nomes/hashes | Basenames exclusivos; diretórios não são preservados |
| JSON ambíguo | Parser estrito; duplicatas e propriedades perigosas proibidas | Subconjunto JSON de profundidade limitada |
| DoS com entradas enormes | Limites de arquivo, total, assinaturas e profundidade | Hashing pode consumir até 1 GiB |
| Vazamento de segredos via exceção | Mensagens genéricas de erro | Falhas de outros componentes podem revelar dados |
| Traversal/symlinks | `lstat`, `O_NOFOLLOW` quando possível e `fstat` | TOCTOU em diretórios ancestrais |
| Replay de atestação | Commit fixado na política | Reuso do mesmo commit é possível; sem timestamp externo |
| Pipeline de build comprometida | Não há validação independente do builder | Adote runners protegidos, OIDC e serviços de atestação |

## Não objetivos

A ferramenta não procura CVEs, segredos em repositórios, configurações de servidor ou malware. Não executa artefatos. Não substitui Sigstore, Cosign, Rekor, Fulcio, TUF, SLSA verifier nem GitHub Artifact Attestations. O uso da sintaxe SLSA Provenance v1 não certifica aderência a níveis SLSA.

## Testes adversariais

Os testes cobrem adulteração de conteúdo, quórum insuficiente, chaves desconhecidas, troca de commit, identidade divergente, JSON duplicado, links simbólicos e permissões das chaves. Não representam auditoria independente.
