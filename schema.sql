CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    nome TEXT NOT NULL,
    data_criacao TEXT NOT NULL DEFAULT (DATETIME('now')),
    status TEXT CHECK( status IN ('ativo', 'bloqueado') ) NOT NULL DEFAULT 'ativo',
    data_ultima_atualizacao TEXT,
    role TEXT CHECK( role IN ('admin', 'user') ) DEFAULT 'user'
);
