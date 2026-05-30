
create database HMyshop$shop;
use HMyshop$shop;

-- =====================================
-- 1. Users Table
-- =====================================
CREATE TABLE Users (
    userid Varchar(255) PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user','owner','admin') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================
-- 2. Shops Table
-- =====================================
CREATE TABLE Shops (
    shopid INT auto_increment PRIMARY KEY,
    userid Varchar(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    tax_id VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE
);

-- =====================================
-- 3. Categories Table
-- =====================================
CREATE TABLE Categories (
    categories_id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

-- =====================================
-- 4. Products Table
-- =====================================
CREATE TABLE Products (
    product_id SERIAL PRIMARY KEY,
    shopid INT NOT NULL,
    categoryid BIGINT UNSIGNED NOT NULL,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    tax DECIMAL(5,2) NOT NULL DEFAULT 0,
    stock INT NOT NULL DEFAULT 0,
    safe_stock INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE,
    FOREIGN KEY (categoryid) REFERENCES Categories(categories_id) ON DELETE CASCADE
);

-- =====================================
-- 5. Carts Table
-- =====================================
CREATE TABLE Carts (
    cartid SERIAL PRIMARY KEY,
    userid VARCHAR(255) NOT NULL,
    shopid INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
);

-- =====================================
-- 6. Cart_Items Table
-- =====================================
CREATE TABLE Cart_Items (
    cartid BIGINT UNSIGNED NOT NULL,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    FOREIGN KEY (cartid) REFERENCES Carts(cartid) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE
);

-- =====================================
-- 7. Orders Table
-- =====================================
CREATE TABLE Orders (
    orderid SERIAL PRIMARY KEY,
    userid VARCHAR(255) NOT NULL,
    shopid INT NOT NULL,
    total_price DECIMAL(10,2) NOT NULL DEFAULT 0,
    status ENUM('pending','confirmed','shipped','delivered','cancelled') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
);

-- =====================================
-- 8. Order_Items Table
-- =====================================
CREATE TABLE Order_Items (
    id SERIAL PRIMARY KEY,
    product_id BIGINT UNSIGNED NOT NULL,
    orderid BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    price DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (orderid) REFERENCES Orders(orderid) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE
);

create table order_descriptions(
    orderid serial primary key,
    userid varchar(255) not null,
    shopid int not null,
    phone INT(15) not null,
    street varchar(255) not null,
    city varchar(100) not null,
    state varchar(100) not null,
    zip_code varchar(20) not null,
    country varchar(100) not null,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (orderid) REFERENCES Orders(orderid) ON DELETE CASCADE,
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
);




-- 1) Add tax_amount to orders
ALTER TABLE Orders ADD COLUMN tax_amount DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER total_price;

-- 2) Add order_id alias to Order_Items (keep orderid for compatibility)
ALTER TABLE Order_Items ADD COLUMN order_id BIGINT UNSIGNED NULL AFTER id;
UPDATE Order_Items SET order_id = orderid;
-- Optional: keep both columns, then app can use order_id; later you can drop orderid after migrating references.

-- 3) Add shop_id columns (aliases) and/or populate them
ALTER TABLE Products ADD COLUMN shop_id INT NULL AFTER product_id;
UPDATE Products SET shop_id = shopid;
ALTER TABLE Carts ADD COLUMN shop_id INT NULL AFTER cartid;
UPDATE Carts SET shop_id = shopid;
-- Add indexes/foreign keys as needed (do this carefully to avoid FK conflicts).

-- 4) Rename phone to varchar and add a proper id column on order_descriptions
ALTER TABLE order_descriptions MODIFY phone VARCHAR(32) NOT NULL;
ALTER TABLE order_descriptions CHANGE orderid order_desc_id INT AUTO_INCREMENT PRIMARY KEY;
ALTER TABLE order_descriptions ADD COLUMN order_id INT NOT NULL;
-- Then populate order_id appropriately and add FK to Orders(orderid)
-- (These changes are more intrusive — test first.)

-- 5) Create synonyms or views if you prefer to keep current schema:
CREATE VIEW order_items AS SELECT id, orderid AS order_id, product_id, quantity, price FROM Order_Items;
CREATE VIEW orders AS SELECT orderid AS order_id, userid, shopid, total_price, status, created_at FROM Orders;

CREATE TABLE product_desc (
    product_id BIGINT UNSIGNED NOT NULL,
    description1 VARCHAR(244),
    description2 VARCHAR(244),
    description3 VARCHAR(244),
    description4 VARCHAR(244),
    description5 VARCHAR(244),
    CONSTRAINT fk_product_desc_product
        FOREIGN KEY (product_id)
        REFERENCES Products(product_id)
) ENGINE=InnoDB;

ALTER TABLE Orders 
MODIFY COLUMN status 
ENUM('pending','confirmed','shipped','delivered','cancelled','return_requested','request_accepted','returned') 
NOT NULL DEFAULT 'pending';

CREATE TABLE rating (
    rating_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    product_id BIGINT UNSIGNED NOT NULL,
    userid VARCHAR(255) NOT NULL,
    rating_value TINYINT NOT NULL CHECK (rating_value >= 1 AND rating_value <= 5),
    rating_title VARCHAR(100),
    rating_comment TEXT,
    helpful_count INT DEFAULT 0,
    verified_purchase BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Foreign keys
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,

    -- Unique constraint
    UNIQUE KEY unique_user_product (userid, product_id),

    -- Indexes
    INDEX idx_product_id (product_id),
    INDEX idx_user_id (userid),
    INDEX idx_rating_value (rating_value),
    INDEX idx_created_at (created_at),
    INDEX idx_verified_purchase (verified_purchase)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;