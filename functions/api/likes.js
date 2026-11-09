-- Таблица лайков: один девайс (cookie) = одна строка
CREATE TABLE IF NOT EXISTS likes (
  device  TEXT PRIMARY KEY,
  created INTEGER NOT NULL
);

-- Счётчик попыток с одного IP за день (хранится только хеш с солью, старые дни удаляются)
CREATE TABLE IF NOT EXISTS ip_hits (
  h   TEXT NOT NULL,
  day TEXT NOT NULL,
  n   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (h, day)
);
