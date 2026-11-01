# Relatório de qualidade — Provenance Gate v0.1.0

## Testes locais executados

- `npm run check`: PASS — sintaxe de quatro módulos principais.
- `npm test`: PASS — **33 testes** de unidade, CLI e cenários adversariais.
- `npm run demo`: PASS — assinatura 2-de-2 e alteração de bytes rejeitada.
- `npm audit --audit-level=high`: PASS — nenhuma vulnerabilidade reportada na execução.
- `npm pack --dry-run --ignore-scripts`: PASS — empacotamento validado.

## Cenários de segurança verificados

1. DSSE PAE vincula payload e tipo de conteúdo.
2. Duas chaves independentes satisfazem quórum 2-de-2.
3. Uma única assinatura não satisfaz política 2-de-2.
4. Hash SHA-256 rejeita bytes adulterados e arquivos não listados.
5. Payload adulterado invalida assinatura Ed25519.
6. Troca de commit, builder, buildType ou repositório rejeitada.
7. Chave pública desconhecida não entra na raiz de confiança.
8. Duplicatas de chave e de key IDs são rejeitadas.
9. JSON malformado ou ambíguo com chaves repetidas é recusado.
10. Links simbólicos, chave privada com permissão indevida e erros de I/O são tratados.
11. CLI usa código 1 para falha de política e 2 para operação incompleta.
12. Mensagens de erro omitem conteúdo PEM, payloads e caminhos sensíveis.

## Validação remota

A matriz do GitHub Actions foi configurada para **Ubuntu, Windows e macOS / Node.js 22 e 24**, com verificação sintática, 33 testes, empacotamento e auditoria npm. Consulte a aba Actions para o resultado efetivo por commit; a aprovação local não substitui a execução no GitHub.

## Limites do ensaio

- Não houve auditoria criptográfica independente.
- Não há validação real de identidade OIDC, execução remota do build ou transparência pública.
- Não há publicação automática no registro npm.
- Desempenho e resistência a alterações concorrentes em arquivos de 512 MiB não foram exaustivamente testados.

Um teste de regressão bem-sucedido não certifica a segurança em produção.
