
-- Users table
CREATE TABLE Users (
    userid VARCHAR(255) PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user','owner','admin') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_email (email),
    INDEX idx_users_role (role),
    INDEX idx_users_created (created_at)
) ENGINE=InnoDB;

-- Shops table
CREATE TABLE Shops (
    shopid INT PRIMARY KEY AUTO_INCREMENT,
    userid VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    Address VARCHAR(255) NOT NULL default "N/A",
    phone VARCHAR(20) NOT NULL default "N/A",
    GSTN VARCHAR(50) NOT NULL default "N/A",
    tax_id VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    INDEX idx_shops_userid (userid),
    INDEX idx_shops_name (name),
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE
);

-- Categories table
CREATE TABLE Categories (
    categories_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    shopid int not null,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    INDEX idx_categories_shopid (shopid),
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE,
    INDEX idx_categories_name (name)
) ENGINE=InnoDB;

-- Products table
CREATE TABLE Products (
    product_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    SPID VARCHAR(255) NOT NULL default "N/A",
    categoryid BIGINT UNSIGNED NOT NULL,
    name VARCHAR(100) NOT NULL,
    image VARCHAR(255),
    HSN_code VARCHAR(50),
    location VARCHAR(255) NOT NULL default "N/A",
    status varchar(255) not null default "active",
    price DECIMAL(10,2) NOT NULL,
    Bprice DECIMAL(10,2) NOT NULL,
    Unit VARCHAR(50) NOT NULL default "N/A",
    tax DECIMAL(5,2) NOT NULL DEFAULT 0.00,
    stock INT NOT NULL DEFAULT 0,
    safe_stock INT NOT NULL DEFAULT 0,
    shop_id INT NOT NULL,   
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL,
    INDEX idx_products_category (categoryid),
    INDEX idx_products_shop (shop_id),
    INDEX idx_products_name (name),
    INDEX idx_products_price (price),
    INDEX idx_products_stock (stock),
    INDEX idx_products_created (created_at),
    FULLTEXT INDEX idx_products_search (name),
    FOREIGN KEY (categoryid) REFERENCES Categories(categories_id) ON DELETE CASCADE,
    FOREIGN KEY (shop_id) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Product descriptions table
CREATE TABLE product_desc (
    product_id BIGINT UNSIGNED NOT NULL,
    description1 VARCHAR(244),
    description2 VARCHAR(244),
    description3 VARCHAR(244),
    description4 VARCHAR(244),
    description5 VARCHAR(244),
    PRIMARY KEY (product_id),
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Carts table
CREATE TABLE Carts (
    cartid BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    userid VARCHAR(255) NOT NULL,
    shopid INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_carts_user (userid),
    INDEX idx_carts_shop (shopid),
    INDEX idx_carts_user_shop (userid, shopid),
    INDEX idx_carts_created (created_at),
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE,
    UNIQUE KEY unique_user_shop_cart (userid, shopid)
) ENGINE=InnoDB;

-- Cart Items table
CREATE TABLE cart_items (
    cartid BIGINT UNSIGNED NOT NULL,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    PRIMARY KEY (cartid, product_id),
    INDEX idx_cartitems_product (product_id),
    INDEX idx_cartitems_quantity (quantity),
    FOREIGN KEY (cartid) REFERENCES Carts(cartid) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Orders table
CREATE TABLE Orders (
    orderid BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    userid VARCHAR(255) NOT NULL,
    shopid INT NOT NULL,
    total_price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    tax_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    status ENUM('pending','confirmed','shipped','delivered','cancelled','return_requested','request_accepted','returned') NOT NULL DEFAULT 'pending',
    delivered_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    return_request TIMESTAMP NULL,
    INDEX idx_orders_user (userid),
    INDEX idx_orders_shop (shopid),
    INDEX idx_orders_status (status),
    INDEX idx_orders_created (created_at),
    INDEX idx_orders_user_status (userid, status),
    INDEX idx_orders_shop_status (shopid, status),
    INDEX idx_orders_delivered (delivered_at),
    INDEX idx_orders_return (return_request),
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Order Items table
CREATE TABLE order_items (
    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    orderid BIGINT UNSIGNED NOT NULL,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    price DECIMAL(10,2) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_orderitems_order (orderid),
    INDEX idx_orderitems_product (product_id),
    INDEX idx_orderitems_order_product (orderid, product_id),
    FOREIGN KEY (orderid) REFERENCES Orders(orderid) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Order Descriptions table
CREATE TABLE order_descriptions (
    orderid BIGINT UNSIGNED PRIMARY KEY,
    userid VARCHAR(255) NOT NULL,
    shopid INT NOT NULL,
    phone VARCHAR(32) NOT NULL,
    street VARCHAR(255) NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    zip_code VARCHAR(20) NOT NULL,
    country VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_orderdesc_user (userid),
    INDEX idx_orderdesc_shop (shopid),
    INDEX idx_orderdesc_location (city, state, country),
    INDEX idx_orderdesc_zip (zip_code),
    FOREIGN KEY (orderid) REFERENCES Orders(orderid) ON DELETE CASCADE,
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Rating table
CREATE TABLE rating (
    rating_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    product_id BIGINT UNSIGNED NOT NULL,
    userid VARCHAR(255) NOT NULL,
    rating_value TINYINT NOT NULL,
    rating_title VARCHAR(100),
    rating_comment TEXT,
    helpful_count INT DEFAULT 0,
    verified_purchase TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_rating_product (product_id),
    INDEX idx_rating_user (userid),
    INDEX idx_rating_value (rating_value),
    INDEX idx_rating_verified (verified_purchase),
    INDEX idx_rating_created (created_at),
    INDEX idx_rating_product_value (product_id, rating_value),
    INDEX idx_rating_helpful (helpful_count),
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    FOREIGN KEY (userid) REFERENCES Users(userid) ON DELETE CASCADE,
    UNIQUE KEY unique_user_product_rating (userid, product_id)
) ENGINE=InnoDB;

CREATE TABLE Returns (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_item_id BIGINT UNSIGNED NOT NULL,
    order_id BIGINT UNSIGNED NOT NULL,
    user_id VARCHAR(255) not null,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    reason TEXT,
    status ENUM('pending', 'approved', 'rejected', 'pickup_scheduled', 'picked_up', 'processed', 'refunded') DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL,
    pickup_scheduled_at TIMESTAMP NULL,
    picked_up_at TIMESTAMP NULL,
    processed_at TIMESTAMP NULL,
    refunded_at TIMESTAMP NULL,
    rejection_reason TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Add foreign keys with proper references
    CONSTRAINT fk_returns_order_item 
        FOREIGN KEY (order_item_id) 
        REFERENCES order_items(id)
        ON DELETE RESTRICT 
        ON UPDATE RESTRICT,
        
    CONSTRAINT fk_returns_order 
        FOREIGN KEY (order_id) 
        REFERENCES Orders(orderid)
        ON DELETE RESTRICT 
        ON UPDATE RESTRICT,
        
    CONSTRAINT fk_returns_user 
        FOREIGN KEY (user_id) 
        REFERENCES Users(userid)
        ON DELETE RESTRICT 
        ON UPDATE RESTRICT,
        
    CONSTRAINT fk_returns_product 
        FOREIGN KEY (product_id)
        REFERENCES Products(product_id)  -- Note: it's product_id, not id
        ON DELETE RESTRICT 
        ON UPDATE RESTRICT
);


CREATE TABLE IF NOT EXISTS Invoices (
    invoice_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    QID BIGINT UNSIGNED,
    invoice_number VARCHAR(50) NOT NULL,
    customer_name VARCHAR(100) NOT NULL,
    customer_email VARCHAR(100) NOT NULL,
    customer_phone VARCHAR(20),
    customer_address TEXT,
    due_date DATE NOT NULL,
    shop_id INT NOT NULL,
    subtotal DECIMAL(10,2) NOT NULL,
    total_tax DECIMAL(10,2) NOT NULL,
    cgst DECIMAL(10,2) NOT NULL DEFAULT 0,
    sgst DECIMAL(10,2) NOT NULL DEFAULT 0,
    igst DECIMAL(10,2) NOT NULL DEFAULT 0,
    grand_total DECIMAL(10,2) NOT NULL,
    status ENUM('draft', 'sent', 'paid', 'cancelled') DEFAULT 'draft',
    cancelled_note text,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by INT,
    INDEX idx_invoice_number (invoice_number),
    INDEX idx_customer_email (customer_email),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    foreign key (shop_id) references Shops(shopid) on delete cascade,
    foreign key (QID) references Quotations(QID) on delete set null
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Invoice_Items (
    item_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    invoice_id BIGINT UNSIGNED NOT NULL,
    product_id BIGINT UNSIGNED,
    description VARCHAR(255) NOT NULL,
    quantity INT NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    tax_rate DECIMAL(5,2) NOT NULL,
    tax_amount DECIMAL(10,2) NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (invoice_id) REFERENCES Invoices(invoice_id) ON DELETE CASCADE,
    INDEX idx_invoice_id (invoice_id),
    INDEX idx_product_id (product_id)
)engine=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS customer(
    customer_id BIGINT unsigned AUTO_INCREMENT PRIMARY KEY,
    customer_name varchar(244) not null,
    customer_mobile_number varchar(13) not null,
    address1 varchar(244) not null,
    address2 varchar(244),
    city varchar(244) not null,
    pincode varchar(6) not null,
    Vilage  varchar(244) not null,
    email varchar(244) not null,
    GSTN varchar(50) not null default "N/A",
    Bank_IFSC varchar(50) not null default "N/A",
    Bank_Account_Number varchar(50) not null default "N/A",
    Bank_Name varchar(244) not null default "N/A",
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by varchar(255) not null,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by varchar(255) not null,
    INDEX idx_customer_id (customer_id));


CREATE TABLE user_customer(
    customer_id BIGINT unsigned not null,
    email VARCHAR(255),
    shopid int,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
);

ALTER TABLE Users
ADD COLUMN reset_token varchar(255) DEFAULT NULL,
ADD COLUMN token_expiry datetime DEFAULT NULL;

ALTER TABLE user_customer
ADD PRIMARY KEY (customer_id, email, shopid);

ALTER TABLE user_customer
ADD CONSTRAINT user_customer_ibfk_2
FOREIGN KEY (customer_id)
REFERENCES customer(customer_id)
ON DELETE CASCADE;

create table purchase_reciepts(
    receipt_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    shopid INT NOT NULL,
    supplier_id BIGINT UNSIGNED NOT NULL,
    Reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE,
    FOREIGN KEY (supplier_id) REFERENCES supplier(supplier_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table purchase_orders(
    PONO BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    PRID BIGINT UNSIGNED NOT NULL,
    supplier_id BIGINT UNSIGNED NOT NULL,
    shopid INT NOT NULL,
    Status ENUM('Approved', 'Incomplete', 'rejected', 'received', 'pending') DEFAULT 'pending',
    tax DECIMAL(5,2) NOT NULL,
    QTY DECIMAL(10,2) NOT NULL,
    recieved_QTY DECIMAL(10,2) NOT NULL default 0,
    price DECIMAL(10,2) NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (PRID) REFERENCES purchase_reciepts(receipt_id) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE,
    FOREIGN KEY (supplier_id) REFERENCES supplier(supplier_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table price_info(
    price_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    INFO_NO VARCHAR(25) NOT NULL,
    product_id BIGINT UNSIGNED NOT NULL,
    shopid INT NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at datetime DEFAULT NULL,
    prev_exp datetime default NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table Quotations(
    QID BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    customer_id BIGINT UNSIGNED NOT NULL,
    shopid INT NOT NULL,
    subtotal DECIMAL(10,2) NOT NULL,
    total_tax DECIMAL(10,2) NOT NULL,
    cgst DECIMAL(10,2) NOT NULL,
    sgst DECIMAL(10,2) NOT NULL,
    igst DECIMAL(10,2) NOT NULL,
    grand_total DECIMAL(10,2) NOT NULL,
    status ENUM('draft', 'sent', 'accepted', 'rejected') DEFAULT 'draft',
    payment_terms VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (customer_id) REFERENCES customer(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table quotation_items(
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    shopid INT NOT NULL,
    QID BIGINT UNSIGNED NOT NULL,
    product_id BIGINT UNSIGNED,
    quantity INT NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    tax_rate DECIMAL(5,2) NOT NULL,
    tax_amount DECIMAL(10,2) NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (QID) REFERENCES Quotations(QID) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    foreign key (shopid) references Shops(shopid) on delete cascade
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table gate_reciept(
    gate_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    product_id BIGINT UNSIGNED NOT NULL,
    PONO BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL,
    shopid INT NOT NULL,
    Reason TEXT,
    payment_status ENUM('paid', 'unpaid') DEFAULT 'unpaid',
    invno varchar(255) not null default "N/A",
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;    

create table stock_adjustment(
    adjustment_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL,
    shopid INT NOT NULL,
    Reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table stock_transfer(
    transfer_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL,
    from_shopid INT NOT NULL,
    to_shopid INT NOT NULL,
    Reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    FOREIGN KEY (from_shopid) REFERENCES Shops(shopid) ON DELETE CASCADE,
    FOREIGN KEY (to_shopid) REFERENCES Shops(shopid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table Sales_order(
    SONO BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    customerid BIGINT UNSIGNED NOT NULL,
    shopid INT NOT NULL,
    subtotal DECIMAL(10,2) NOT NULL,
    total_tax DECIMAL(10,2) NOT NULL,
    cgst DECIMAL(10,2) NOT NULL default 0,
    sgst DECIMAL(10,2) NOT NULL default 0,
    igst DECIMAL(10,2) NOT NULL default 0,
    created_by varchar(255) not null,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL default "N/A",
    FOREIGN KEY (shopid) REFERENCES Shops(shopid) ON DELETE CASCADE,
    FOREIGN KEY (customerid) REFERENCES customer(customer_id) ON DELETE CASCADE
);

create table sales_item(
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    shopid INT NOT NULL,
    SONO BIGINT UNSIGNED not null,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    tax_rate DECIMAL(5,2) NOT NULL,
    tax_amount DECIMAL(10,2) NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (SONO) REFERENCES Sales_order(SONO) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    foreign key (shopid) references Shops(shopid) on delete cascade
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table IF NOT EXISTS PR_items(
    id bigint unsigned primary key auto_increment,
    shopid int not null,
    PRID BIGINT UNSIGNED,
    product_id BIGINT UNSIGNED NOT NULL,
    quantity int not null,
    unit_price decimal(10,2) not null,
    tax_rate decimal(5,2) not null,
    tax_amount decimal(10,2) not null,
    total decimal(10,2) not null,
    FOREIGN KEY (PRID) REFERENCES purchase_reciepts(receipt_id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE,
    foreign key (shopid) references Shops(shopid) on delete cascade
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

create table supplier_invoice(
    invoice_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    invoice_number VARCHAR(50) NOT NULL,
    PONO BIGINT UNSIGNED NOT NULL,
    supplier_id BIGINT UNSIGNED NOT NULL,
    due_date DATE NOT NULL,
    shop_id INT NOT NULL,
    subtotal DECIMAL(10,2) NOT NULL,
    total_tax DECIMAL(10,2) NOT NULL,
    cgst DECIMAL(10,2) NOT NULL,
    sgst DECIMAL(10,2) NOT NULL,
    igst DECIMAL(10,2) NOT NULL,
    grand_total DECIMAL(10,2) NOT NULL,
    status ENUM('draft', 'sent', 'paid', 'cancelled') DEFAULT 'draft',
    cancelled_note text,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by INT,
    INDEX idx_supplier_invoice_number (invoice_number),
    INDEX idx_supplier_status (status),
    INDEX idx_supplier_created_at (created_at),
    INDEX idx_supplier_PONO (PONO),
    FOREIGN KEY (PONO) REFERENCES purchase_orders(PONO) ON DELETE CASCADE,
    foreign key (shop_id) references Shops(shopid) on delete cascade,
    foreign key (supplier_id) references supplier(supplier_id) on delete cascade
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE Products 
ADD UNIQUE KEY uk_product_location_status (name, location, status, shop_id);

create table supplier(
    supplier_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    shop_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    phone VARCHAR(20),
    Pincode VARCHAR(10),
    state  VARCHAR(100),
    city VARCHAR(100),
    country VARCHAR(100),
    address TEXT,
    GSTN VARCHAR(50) unique NOT NULL default "N/A",
    Bank_IFSC VARCHAR(50) NOT NULL default "N/A",
    Bank_Account_Number VARCHAR(50) NOT NULL default "N/A",
    Bank_Name VARCHAR(244) NOT NULL default "N/A",
    Payment_Terms VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by varchar(255) not null,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by varchar(255) not null,
    foreign key (shop_id) references Shops(shopid) on delete cascade
);