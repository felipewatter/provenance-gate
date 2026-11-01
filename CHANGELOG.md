# Changelog

## [0.1.0] — 2026-10-31

- Implementação inicial de **Provenance Gate**, CLI para controles offline de procedência de artefatos.
- Criação de chaves Ed25519 e assinaturas DSSE (PAE) sobre in-toto Statement v1, perfil SLSA Provenance v1.
- Atestação, coassinatura e verificação de quórum M-de-N de chaves confiáveis distintas.
- Políticas de confiança externas com verificação de repositório, commit Git completo, identidade do builder e buildType.
- SHA-256 em streaming e igualdade exata de conjuntos de artefatos.
- Rejeição de JSON malformado, chaves duplicadas, base64 não canônico e chaves não permitidas.
- Limites de memória, tamanho, arquivos e profundidade; I/O com proteção contra symlink e falha fechada.
- CLI com códigos 0/1/2 e relatórios JSON; suíte de regressão e CI multiplataforma Node 22/24.
- Documentação de arquitetura, modelo de ameaças, divulgação responsável e licença MIT.

**Aviso:** os campos de proveniência são fornecidos por signatários; esta versão não valida remotamente a identidade do executor nem comprova um nível SLSA.