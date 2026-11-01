# Tutorial reproduzível — assinatura e validação 2-de-2

Este exemplo usa apenas **chaves descartáveis**. Os dados de build são declarados pelo signatário: a assinatura não comprova que uma pipeline de CI remota realmente produziu o arquivo.

## Demo automática

```bash
npm run demo
```

A demonstração cria duas chaves Ed25519, um artefato e uma atestação com quórum 2-de-2; aprova o original, modifica os bytes e rejeita o arquivo adulterado. Os materiais temporários são apagados ao final.

## Passo a passo (Unix)

```bash
mkdir -p demo
chmod 700 demo
printf 'conteudo-de-release-de-exemplo\n' > demo/app.tar.gz
node src/cli.js keygen --private demo/builder.key.pem --public demo/builder.pub.pem
node src/cli.js keygen --private demo/reviewer.key.pem --public demo/reviewer.pub.pem
```

### 1. Criar declaração assinada

```bash
node src/cli.js attest \
  --artifact demo/app.tar.gz \
  --key demo/builder.key.pem \
  --repository https://github.com/felipewatter/provenance-gate \
  --commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --builder https://github.com/actions/runner/github-hosted \
  --build-type https://example.org/buildtypes/demo/v1 \
  --output demo/first.intoto.json
```

Em projetos reais, informe o SHA completo **verdadeiro** do commit e use uma identidade de builder acordada; `aaaa...` é apenas uma demonstração de igualdade.

### 2. Coassinar sem modificar a declaração

```bash
node src/cli.js cosign \
  --attestation demo/first.intoto.json \
  --key demo/reviewer.key.pem \
  --output demo/two-signers.intoto.json
```

### 3. Criar política aprovada por canal independente

```bash
node src/cli.js policy-create \
  --public demo/builder.pub.pem \
  --public demo/reviewer.pub.pem \
  --threshold 2 \
  --repository https://github.com/felipewatter/provenance-gate \
  --commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --builder https://github.com/actions/runner/github-hosted \
  --build-type https://example.org/buildtypes/demo/v1 \
  --output demo/policy.json
```

**Nunca confie automaticamente em uma política fornecida pelo próprio distribuidor não confiável do artefato.** Revise as chaves públicas e a identidade de origem.

### 4. Verificar artefato e atestação

```bash
node src/cli.js verify \
  --attestation demo/two-signers.intoto.json \
  --policy demo/policy.json \
  --artifact demo/app.tar.gz --json
```

A saída esperada contém `verified: true`, `trustedSigners: 2` e `artifacts: 1`.

### 5. Adulteração

```bash
printf 'CONTEUDO ADULTERADO\n' > demo/app.tar.gz
node src/cli.js verify \
  --attestation demo/two-signers.intoto.json \
  --policy demo/policy.json \
  --artifact demo/app.tar.gz
```

O código de saída **1** bloqueia a distribuição: os bytes já não correspondem ao SHA-256 assinado.

## Windows e PowerShell

Os comandos `node src/cli.js` funcionam com os mesmos argumentos, usando caminhos apropriados ao Windows. Use `$LASTEXITCODE`; `1` ou `2` devem impedir a publicação.

## CI/CD

```yaml
- name: Verify release provenance
  run: |
    node src/cli.js verify \
      --attestation dist/release.intoto.json \
      --policy trust/release-policy.json \
      --artifact dist/app.tar.gz --json
```

O verificador precisa apenas das chaves públicas confiáveis. Para identidade OIDC e logs de transparência verificados, complemente com GitHub Artifact Attestations e Sigstore.

Consulte `SECURITY.md`, `docs/ARCHITECTURE.md` e `docs/THREAT_MODEL.md`.
