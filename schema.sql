-- Cleanup (Use with caution!)
DROP VIEW IF EXISTS active_storefront;
DROP TABLE IF EXISTS reviews, order_products, cart, orders, addresses, payment_methods, products, users CASCADE;

-- USERS: Hard Delete allowed to free up email & respect privacy
CREATE TABLE users (
    id serial PRIMARY KEY,
    password_hash varchar(255) NOT NULL,
    first_name varchar(255) NOT NULL,
    last_name varchar(255) NOT NULL,
    email varchar(255) UNIQUE NOT NULL
);

-- PRODUCTS: Soft Delete (is_active) to preserve sales history
CREATE TABLE products (
    id serial PRIMARY KEY,
    name varchar(255) NOT NULL,
    description text,
    price numeric(10,2) NOT NULL,
    stock_quantity integer NOT NULL DEFAULT 0,
    created_at timestamp DEFAULT now(),
    is_active boolean DEFAULT true
);

-- ADDRESSES: User's personal address book
CREATE TABLE addresses (
    id serial PRIMARY KEY,
    user_id integer REFERENCES users(id) ON DELETE CASCADE,
    street_address text NOT NULL,
    city varchar(100) NOT NULL,
    state varchar(100), -- Nullable for international support
    postal_code varchar(20) NOT NULL,
    is_default boolean DEFAULT false
);

-- ORDERS: Stores a JSONB snapshot of the address at time of purchase
CREATE TABLE orders (
    id serial PRIMARY KEY,
    user_id integer REFERENCES users(id) ON DELETE SET NULL, -- Keep order if user is deleted
    total_cost numeric(10,2) NOT NULL,
    shipping_address jsonb NOT NULL, 
    payment_status varchar(20) DEFAULT 'pending', 
    created_at timestamp DEFAULT now()
);

-- ORDER_PRODUCTS: The line items. RESTRICT product deletion to protect history
CREATE TABLE order_products (
    order_id integer NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id integer NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    quantity integer NOT NULL CHECK (quantity > 0),
    price numeric(10,2) NOT NULL, -- Price at the moment of sale
    UNIQUE (order_id, product_id)
);

-- CART: Temporary storage (disappears if user or product is deleted)
CREATE TABLE cart (
    user_id integer REFERENCES users(id) ON DELETE CASCADE,
    product_id integer REFERENCES products(id) ON DELETE CASCADE,
    quantity integer DEFAULT 1 CHECK (quantity > 0),
    UNIQUE (user_id, product_id)
);

-- REVIEWS: Verified purchase tracking
CREATE TABLE reviews (
    id serial PRIMARY KEY,
    user_id integer REFERENCES users(id) ON DELETE SET NULL,
    product_id integer REFERENCES products(id) ON DELETE CASCADE,
    rating integer NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment text,
    is_verified boolean DEFAULT false,
    created_at timestamp DEFAULT now(),
    UNIQUE (user_id, product_id) 
);

-- VIEW: The "Storefront" layer (Filters out inactive/out-of-stock items)
CREATE VIEW active_storefront AS
SELECT * FROM products 
WHERE is_active = true AND stock_quantity > 0;