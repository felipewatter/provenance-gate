# Política de segurança — Provenance Gate

## Divulgação responsável

Reporte vulnerabilidades utilizando **GitHub Private Vulnerability Reporting / Security Advisories**, se habilitado. Não publique chaves de assinatura, artefatos privados, arquivos de política de uma organização real nem hashes vinculados a dados sensíveis em issues abertas.

## Propriedades implementadas

1. **Autenticidade DSSE**: assinaturas Ed25519 são calculadas sobre a **Pre-Authentication Encoding (PAE)** do payload *e do seu tipo*, conforme o modelo DSSE. Não assina apenas o hash do JSON.
2. **Confiança externa**: chaves públicas aprovadas vêm do arquivo de política fornecido separadamente, **nunca da própria atestação**. `keyid` é dica de localização, validada contra a hash SHA-256 de chave pública SPKI DER.
3. **Quórum**: exige o número configurado de signatários confiáveis distintos. Assinaturas repetidas da mesma chave não contam duas vezes. Chaves desconhecidas não contam.
4. **Política de origem**: repositório HTTPS, commit Git de 40 dígitos, identidade de builder e buildType são exigidos e devem coincidir exatamente com a política.
5. **Integridade de artefato**: cada arquivo é lido e hasheado em streaming SHA-256; o conjunto de nomes de artefatos deve coincidir exatamente com o conjunto de subjects declarados, sem omissões ou itens extras.
6. **Entrada hostil**: rejeita JSON com chaves duplicadas, chaves perigosas, estruturas profundas, envelopes malformados, base64 não canônico, algoritmos/chaves não suportados e listas excessivas.
7. **Limites**: no máximo 100 artefatos, 512 MiB por arquivo, 1 GiB agregado, 1 MiB por envelope, 64 KiB por política, 20 assinaturas, 32 níveis de objetos JSON. Limites excedidos provocam **exit 2**, não uma aprovação.
8. **I/O defensivo**: recusa arquivos simbólicos, abre descritores com `O_NOFOLLOW` quando disponível e verifica metadados durante o hashing. Artefatos e chaves são gravados com `wx` (sem sobrescrita); chave privada gerada em modo 0600 em Unix. Para chaves privadas importadas, exige ausência de permissões de grupo/outros em Unix.
9. **Saída redigida**: erros operacionais da CLI não exibem trechos PEM, dados de artefatos nem caminhos locais.

## O que **não** é garantido

- **Declaração ≠ prova independente do build**. A assinatura comprova que uma chave confiável assinou o payload, não que o conteúdo autodeclarado seja verdade nem que o processo de build foi seguro. **Não reivindicamos um nível SLSA**.
- Não implementa identidade OIDC, certificados Sigstore/Fulcio, repositório de transparência Rekor, TUF nem atestações keyless do GitHub. Para essas garantias, use as ferramentas oficiais dessas plataformas.
- Não consulta GitHub para verificar que o commit declarado existe nem que o builder realmente executou. Para CI, assine somente após as etapas de build, e mantenha chaves de assinaturas com acesso restrito.
- Uma pessoa com acesso para alterar a **política de confiança e o release** pode substituir as chaves e falsificar uma aprovação. Armazene a política como objeto independente, protegido contra alterações pelo mesmo ator que publica artefatos, e revise seu hash/versão.
- Um atacante com chave privada válida pode emitir declarações falsas. Use operadores separados com quórum ≥2, proteja o material secreto e revogue a chave imediatamente se comprometida por nova política.
- Não fornece anti-replay temporal: o commit pinado impede aceitar outra versão, mas uma atestação antiga referente ao mesmo commit pode ser reapresentada. Versione e distribua políticas com o processo de release.
- Tamanhos, modificações simultâneas e caminhos ancestrais podem sofrer corridas; `O_NOFOLLOW` trata o arquivo final e não substitui snapshots imutáveis, escopo de diretório isolado ou checagens de permissão de diretórios pais.
- O formato in-toto/SLSA desta versão é um **perfil restrito** e não pretende aceitar toda a extensão possível dessas especificações.
- A verificação de dois signatários não comprova separação organizacional entre pessoas nem responsabilidade do conteúdo: duas chaves podem estar sob controle do mesmo operador.

## Política operacional recomendada

- Gere as chaves **fora do repositório**, de preferência em ambiente de build confiável ou HSM; o gerador local existe para demonstração e desenvolvimento.
- Armazene a política em um repositório ou ambiente com controle de alterações independente; use revisão dupla e permissões mínimas.
- Execute `verify` sobre **cópias imutáveis e locais** dos artefatos que serão distribuídos, nunca com um arquivo sendo atualizado em paralelo.
- Não inclua assinaturas ou chaves privadas de produção no controle de versão. Ao revogar uma chave, distribua uma nova política e invalide fluxos antigos.
- Encare erros **1** e **2** como bloqueantes de release.

## Códigos de saída

`0`: verificado ou operação realizada; `1`: assinaturas ou identidade/hash não satisfizeram política; `2`: entrada inválida, falha operacional ou verificação incompleta.