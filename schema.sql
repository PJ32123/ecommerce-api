-- Cleanup (Use with caution!)
DROP VIEW IF EXISTS active_storefront;
DROP TABLE IF EXISTS reviews, order_products, cart, orders, addresses, products, users, signin_attempts CASCADE;

-- USERS: Hard Delete allowed to free up email & respect privacy
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL
);

-- SIGNIN_ATTEMPTS: Track amount of times someone tries to signin with an email address
CREATE TABLE signin_attempts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE,  -- Normalized email
    attempt_count INT DEFAULT 0,
    last_attempt_timestamp TIMESTAMP DEFAULT NOW(),
    is_locked BOOLEAN DEFAULT FALSE
);

-- PRODUCTS: Soft Delete (is_active) to preserve sales history
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price NUMERIC(10,2) NOT NULL,
    stock_quantity INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- ADDRESSES: User's personal address book
CREATE TABLE addresses (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    street_address TEXT NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100), -- Nullable for international support
    postal_code VARCHAR(20) NOT NULL
);

-- ORDERS: Stores a JSONB snapshot of the address at time of purchase
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE SET NULL, -- Keep order if user is deleted
    total_cost NUMERIC(10,2) NOT NULL,
    shipping_address JSONB NOT NULL, 
    payment_status VARCHAR(20) DEFAULT 'pending', 
    created_at TIMESTAMP DEFAULT NOW()
);

-- ORDER_PRODUCTS: The line items. RESTRICT product deletion to protect history
CREATE TABLE order_products (
    order_id INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id INT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    quantity INT NOT NULL CHECK (quantity > 0),
    price NUMERIC(10,2) NOT NULL, -- Price at the moment of sale
    UNIQUE (order_id, product_id)
);

-- CART: Temporary storage (disappears if user or product is deleted)
CREATE TABLE cart (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    product_id INT REFERENCES products(id) ON DELETE CASCADE,
    quantity INT DEFAULT 1 CHECK (quantity > 0),
    UNIQUE (user_id, product_id)
);

-- REVIEWS: Verified purchase tracking
CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE SET NULL,
    product_id INT REFERENCES products(id) ON DELETE CASCADE,
    rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (user_id, product_id) 
);

-- VIEW: The "Storefront" layer (Filters out inactive/out-of-stock items)
CREATE VIEW active_storefront AS
SELECT * FROM products 
WHERE is_active = TRUE AND stock_quantity > 0;