# Contribuindo com o Provenance Gate

A colaboração é bem-vinda. Não publique material secreto em issues, testes ou PRs. Para reportar falhas sensíveis, consulte SECURITY.md.

## Desenvolvimento

Requer Node.js 22 ou 24. Não são necessárias dependências de execução externas.

```bash
npm ci --ignore-scripts
npm run check
npm test
npm audit --audit-level=high
```

## Regras de contribuição

- Segurança por padrão: input inválido ou inspeção incompleta jamais resulta em aprovação.
- Não adicione opções que aceitem chaves públicas do próprio envelope como raiz de confiança.
- Qualquer mudança no formato de atestação, PAE, algoritmo ou na semântica de política exige testes adversariais.
- Nunca inclua chaves privadas de produção, arquivos reais de clientes ou segredos nos commits.
- Atualize README, CHANGELOG, arquitetura e modelo de ameaças quando afetados.
- Prefira commits pequenos, PRs revisáveis e testes em Ubuntu/Windows/macOS.

## Padrões

ES modules, Node.js built-ins, sem dependências de produção por padrão, funções com responsabilidades explícitas, documentação em português brasileiro e mensagens de erro sem dados potencialmente sensíveis.