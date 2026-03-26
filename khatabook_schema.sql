-- Khatabook Accounting Tables

USE shop;

-- Parties table (customers and suppliers)
CREATE TABLE parties (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    type ENUM('customer', 'supplier') NOT NULL,
    balance DECIMAL(10,2) DEFAULT 0.00,
    shop_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_parties_shop (shop_id),
    INDEX idx_parties_type (type),
    INDEX idx_parties_name (name),
    FOREIGN KEY (shop_id) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Transactions table
CREATE TABLE transactions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    party_id INT NOT NULL,
    type ENUM('debit', 'credit') NOT NULL,  -- debit: money given to party (you owe), credit: money received from party (party owes you)
    amount DECIMAL(10,2) NOT NULL,
    description TEXT,
    transaction_date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    shop_id INT NOT NULL,
    INDEX idx_transactions_party (party_id),
    INDEX idx_transactions_date (transaction_date),
    INDEX idx_transactions_shop (shop_id),
    INDEX idx_transactions_created_by (created_by),
    FOREIGN KEY (party_id) REFERENCES parties(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES Users(userid) ON DELETE CASCADE,
    FOREIGN KEY (shop_id) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Trigger to update balance on transaction insert
DELIMITER //
CREATE TRIGGER update_balance_after_insert AFTER INSERT ON transactions
FOR EACH ROW
BEGIN
    IF NEW.type = 'credit' THEN
        UPDATE parties SET balance = balance + NEW.amount WHERE id = NEW.party_id;
    ELSE
        UPDATE parties SET balance = balance - NEW.amount WHERE id = NEW.party_id;
    END IF;
END//
DELIMITER ;

-- Trigger to update balance on transaction update
DELIMITER //
CREATE TRIGGER update_balance_after_update AFTER UPDATE ON transactions
FOR EACH ROW
BEGIN
    -- Reverse old transaction
    IF OLD.type = 'credit' THEN
        UPDATE parties SET balance = balance - OLD.amount WHERE id = OLD.party_id;
    ELSE
        UPDATE parties SET balance = balance + OLD.amount WHERE id = OLD.party_id;
    END IF;
    -- Apply new transaction
    IF NEW.type = 'credit' THEN
        UPDATE parties SET balance = balance + NEW.amount WHERE id = NEW.party_id;
    ELSE
        UPDATE parties SET balance = balance - NEW.amount WHERE id = NEW.party_id;
    END IF;
END//
DELIMITER ;

-- Trigger to update balance on transaction delete
DELIMITER //
CREATE TRIGGER update_balance_after_delete AFTER DELETE ON transactions
FOR EACH ROW
BEGIN
    IF OLD.type = 'credit' THEN
        UPDATE parties SET balance = balance - OLD.amount WHERE id = OLD.party_id;
    ELSE
        UPDATE parties SET balance = balance + OLD.amount WHERE id = OLD.party_id;
    END IF;
END//
DELIMITER ;

ALTER TABLE parties
MODIFY COLUMN phone VARCHAR(20) UNIQUE DEFAULT NULL;