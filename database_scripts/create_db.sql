-- Create the database with modern UTF-8 support
-- Create the database
CREATE DATABASE MUSIC
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_general_ci;

-- Use the new database
USE MUSIC;

-- Create a sample table with FULLTEXT support (example: songs)
CREATE TABLE songs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  artist VARCHAR(255),
  lyrics TEXT,
  FULLTEXT(title, lyrics)
);

-- Insert 3 sample records
INSERT INTO songs (title, artist, lyrics)
VALUES 
  ('Imagine', 'John Lennon', 'Imagine there\'s no heaven, It\'s easy if you try...'),
  ('Bohemian Rhapsody', 'Queen', 'Is this the real life? Is this just fantasy?...'),
  ('Hotel California', 'Eagles', 'On a dark desert highway, cool wind in my hair...');

-- Confirm the inserts
SELECT * FROM songs;
