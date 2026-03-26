from multiprocessing import connection

from flask import Flask, render_template,request,flash,url_for,redirect,session,jsonify
import mysql.connector
import bcrypt, os, re, random, string
from datetime import datetime,timedelta
import json
from werkzeug.utils import secure_filename
import logging
import traceback
from functools import wraps
from flask_cors import CORS
import smtplib,secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            # If AJAX/JSON request, return 401 JSON instead of redirecting
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in (request.headers.get('Accept') or ''):
                return jsonify({"success": False, "message": "Authentication required"}), 401
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        if session.get("role") == "user":
            flash("Access denied. Shop Owners and Admins only.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrap

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app, supports_credentials=True)
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# create the folder if not exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Logging / Debug helpers ---
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
log_file = os.path.join(LOG_DIR, 'app.log')
handler = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
handler.setFormatter(formatter)
root_logger = logging.getLogger()
if not any(isinstance(h, logging.FileHandler) for h in root_logger.handlers):
    root_logger.addHandler(handler)
root_logger.setLevel(logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# Dashboard display limits
MAX_CATEGORIES = 6
MAX_PRODUCTS = 12

def get_db():
    conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="8010",
    database="shop"
    )
    cursor = conn.cursor(dictionary=True)
    return conn, cursor

@app.route('/')
def index():
    return redirect(url_for('dashboard'))


#change
@app.route("/sign_up", methods=['POST'])
def sign_up():
    if "user" in session:
        flash("You are logged out by visited a signup page while logged in. Please login again to continue.", "warning")
        session.clear()
        return redirect(url_for('login'))
    conn, cursor = get_db()
    full_name = request.form.get('full_name')
    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('usertype')
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash("Email already registered. Please log in.", "error")
            return redirect(url_for('login'))
        ##check if customer id exists in customer table
        cursor.execute("select customer_id from customer where email = %s", (email,))
        ids= cursor.fetchall()
        ids = [i.get('customer_id') for i in ids if i.get('customer_id')]
        otp = generate_otp()
        session["signup_data"] = {"full_name": full_name, 
                                  "email": email, 
                                  "username": username, 
                                  "password": hashed_password, 
                                  "role": role, 
                                  "otp": otp,
                                  "ids": ids}
        if send_otp(email, otp):
            flash("OTP sent to your email. Please verify to complete registration.", "info")
            return redirect(url_for("verify_otp"))
        else:
            flash("Failed to send OTP. Please try again.", "error")
            return redirect(url_for('login'))

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "error")

    return redirect(url_for('login'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    if "user" in session:
        flash("You are logged out by visited a login page while logged in. Please login again to continue.", "warning")
        session.clear()
        return redirect(url_for('login'))
    conn, cursor = get_db()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for('login'))

        try:
            cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if not user:
                flash("Invalid email or password.", "error")
                return redirect(url_for('login'))

            stored_password = user['password_hash']
            username = user['userid']
            full_name = user['full_name']
            role = user['role']

            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                session["user"] = username
                session["full_name"] = full_name
                session["role"] = role  # Save role in session
                session["email"]=email

                flash("Login successful!", "success")
                if role == "owner" or role == "admin":
                    return redirect(url_for('admin_dashboard'))
                else:
                    cursor.execute("SELECT shopid FROM user_customer WHERE email = %s", (email,))
                    shop_ids = cursor.fetchall()          
                    if shop_ids:
                        shop_id_list = [shop['shopid'] for shop in shop_ids]
                        session["shop_ids"] = shop_id_list
                        return redirect(url_for('dashboard'))
                    else:
                        flash("No shops linked to this account. Please contact support.", "warning")
                        return redirect(url_for('no_shop_linkedpage'))
            else:
                flash("Invalid email or password.", "error")
                    
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print("LOGIN ERROR:", e)
            print(tb)
            flash(f"Login failed: {e}", "danger")
            return redirect("/login")

        return redirect(url_for('login'))

    return render_template('login.html')


def send_email(receiver_email, subject, body):
    try:
        EMAIL_ADDRESS = "appedairy@gmail.com"
        EMAIL_PASSWORD = "xflz xucw hkxb zpfg"
        SMTP_SERVER = "smtp.gmail.com"
        SMTP_PORT = 587
        msg = MIMEText(body)
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = receiver_email
        msg["Subject"] = subject

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, receiver_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

# Forgot Password Route
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        conn, cursor = get_db()
        cursor.execute("SELECT * FROM Users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:
            reset_token = secrets.token_urlsafe(32)  # Generate token
            expiry_time = datetime.now() + timedelta(hours=1)  # Expiry time

            # Store in database
            cursor.execute("UPDATE Users SET reset_token=%s, token_expiry=%s WHERE email=%s",
                           (reset_token, expiry_time, email))
            conn.commit()
            cursor.close()

            # Create reset link
            reset_link = f"https://dairyapp3412.pythonanywhere.com/reset_password/{reset_token}"

            # Send reset link to email
            email_body = f"Click here to reset your password: {reset_link} (Valid for 1 hour Do not share this link with anyone.)"
            send_email(email, "Password Reset", email_body)

            flash("Password reset link sent to your email.", "success")
        else:
            flash("Email not registered!", "danger")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")



@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn, cursor = get_db()
    cursor.execute("SELECT email, token_expiry FROM Users WHERE reset_token=%s", (token,))
    result = cursor.fetchone()

    if not result:
        flash("Invalid or expired reset link!", "danger")
        return redirect(url_for("forgot_password"))

    email = result.get("email")
    token_expiry = result.get("token_expiry")
    print(f"Email: {email}, Token Expiry: {token_expiry}, Result: {result}")
    if datetime.now() > token_expiry:
        flash("Reset link has expired. Request a new one.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form["password"]
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update new password in the database
        cursor.execute("UPDATE Users SET password_hash=%s, reset_token=NULL, token_expiry=NULL WHERE email=%s",
                       (hashed_password, email))
        conn.commit()
        cursor.close()

        flash("Password successfully reset! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

def verifier(email):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(email, otp):
    try:
        EMAIL_ADDRESS = "appedairy@gmail.com"
        EMAIL_PASSWORD = "xflz xucw hkxb zpfg"
        SMTP_SERVER = "smtp.gmail.com"
        SMTP_PORT = 587
        msg = MIMEText(f"Your OTP for Edairy email verification is: {otp}")
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = email
        msg["Subject"] = "Email Verification OTP"

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print("Error sending OTP:", e)
        return False

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if "signup_data" not in session:
        flash("Session expired! Please sign up again.", "danger")
        return redirect(url_for("signup"))

    if request.method == "POST":
        entered_otp = request.form.get("otp")
        stored_otp = session["signup_data"].get("otp")

        if entered_otp == stored_otp:
            # Store user in the database
            signup_data = session.pop("signup_data")
            print("Signup data being saved:", signup_data)
            conn, cursor = get_db()
            cursor.execute("INSERT INTO Users (email, userid, password_hash, full_name,role,created_at) VALUES (%s, %s, %s, %s,%s,%s)",
                           (signup_data["email"], signup_data["username"], signup_data["password"], signup_data["full_name"],signup_data['role'],datetime.now()))
            conn.commit()
            '''if signup_data["ids"]:
                for id in signup_data["ids"]:
                    cursor.execute("insert into user_customer (customer_id,email) values (%s,%s)",(id,signup_data["email"]))
                    conn.commit()
            cursor.close()'''

            flash("Email verified! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid OTP! Please try again.", "danger")

    return render_template("verify_otp.html")        

@app.route("/no_shop_linkedpage")
@login_required
def no_shop_linkedpage():
    return render_template('blank.html')


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
@login_required
def dashboard():
    conn, cursor = get_db()
    
    try:
        # Set autocommit off for transaction control
        try:
            conn.autocommit = False
        except Exception:
            pass
        
        # Step 1: Get all shop_ids that the current user (customer) is linked to
        user_email = session.get("email")
        shop_ids = []  # Initialize empty list to avoid scope issues
        
        try:
            # Query user_customer table to get shops linked to this email
            cursor.execute(
                "SELECT DISTINCT shopid FROM user_customer WHERE email = %s",
                (user_email,)
            )
            shop_rows = cursor.fetchall()
            shop_ids = [row['shopid'] for row in shop_rows if row.get('shopid')]
            
        except Exception as e:
            app.logger.error(f"Error fetching shops for user: {e}")
            shop_ids = []
        
        # Step 2: Fetch categories from shops the customer is linked to
        cats = []
        if shop_ids:
            try:
                placeholders = ",".join(["%s"] * len(shop_ids))
                query = f"""
                    SELECT DISTINCT c.name
                    FROM Categories c
                    WHERE c.categories_id IN (
                        SELECT DISTINCT p.categoryid 
                        FROM Products p 
                        WHERE p.shop_id IN ({placeholders})
                    )
                    LIMIT %s
                """
                cursor.execute(query, (*shop_ids, MAX_CATEGORIES))
                cats = [row['name'] for row in cursor.fetchall()]
            except Exception as e:
                app.logger.error(f"Error fetching categories: {e}")
                cats = []
        else:
            cats = []
        
        # Step 3: Fetch products with filters
        products = []
        category_id = None  # Initialize to avoid scope issues
        
        # Check for category filter from query params
        category_query = request.args.get('category')
        if category_query:
            try:
                # Try numeric id first
                if re.fullmatch(r"\d+", category_query.strip()):
                    category_id = int(category_query.strip())
                else:
                    # Lookup category id by name
                    cursor.execute(
                        "SELECT categories_id FROM Categories WHERE name = %s LIMIT 1",
                        (category_query,)
                    )
                    row = cursor.fetchone()
                    if row:
                        category_id = row.get('categories_id')
            except Exception as e:
                app.logger.error(f"Error processing category filter: {e}")
                category_id = None
        
        # Fetch products only if shop_ids exist
        if shop_ids:
            try:
                placeholders = ",".join(["%s"] * len(shop_ids))
                
                if category_id:
                    # Products filtered by category and shop
                    query = f"""
                        SELECT
                            p.product_id as id,
                            p.name,
                            p.price,
                            c.name as category,
                            p.stock as stock,
                            COALESCE(AVG(r.rating_value), 0) as rating,
                            COUNT(r.rating_value) as rating_count
                        FROM Products p
                        LEFT JOIN Categories c ON p.categoryid = c.categories_id
                        LEFT JOIN rating r ON p.product_id = r.product_id
                        WHERE p.categoryid = %s 
                        AND p.shop_id IN ({placeholders})
                        GROUP BY p.product_id, p.name, p.price, c.name, p.stock
                        ORDER BY p.product_id DESC
                        LIMIT %s
                    """
                    cursor.execute(query, (category_id, *shop_ids, MAX_PRODUCTS))
                else:
                    # All products from linked shops
                    query = f"""
                        SELECT
                            p.product_id as id,
                            p.name,
                            p.price,
                            c.name as category,
                            p.stock as stock,
                            COALESCE(AVG(r.rating_value), 0) as rating,
                            COUNT(r.rating_value) as rating_count
                        FROM Products p
                        LEFT JOIN Categories c ON p.categoryid = c.categories_id
                        LEFT JOIN rating r ON p.product_id = r.product_id
                        WHERE p.shop_id IN ({placeholders})
                        GROUP BY p.product_id, p.name, p.price, c.name, p.stock
                        ORDER BY p.product_id DESC
                        LIMIT %s
                    """
                    cursor.execute(query, (*shop_ids, MAX_PRODUCTS))
                
                rows = cursor.fetchall()
                
                # Process products
                for row in rows:
                    pid = row.get('id')
                    name = row.get('name')
                    price = float(row.get('price') or 0)
                    category = row.get('category', 'uncategorized')
                    stock = row.get('stock', 0)
                    rating = float(row.get('rating') or 0)
                    rating_count = row.get('rating_count', 0)
                    
                    # Get image URL
                    img_url = get_product_image_url(pid)
                    
                    products.append({
                        'id': pid,
                        'name': name,
                        'price': price,
                        'original_price': None,
                        'discount': 0,
                        'stock': stock,
                        'rating': rating,
                        'rating_count': rating_count,
                        'image': img_url,
                        'category': category
                    })
                    
            except Exception as e:
                app.logger.error(f"Error fetching products: {e}")
                # Fallback query without ratings
                try:
                    if category_id:
                        placeholders = ",".join(["%s"] * len(shop_ids))
                        query = f"""
                            SELECT 
                                p.product_id as id, 
                                p.name, 
                                p.price, 
                                c.name as category,
                                p.stock 
                            FROM Products p
                            LEFT JOIN Categories c ON p.categoryid = c.categories_id
                            WHERE p.categoryid = %s 
                            AND p.shop_id IN ({placeholders})
                            ORDER BY p.product_id DESC 
                            LIMIT %s
                        """
                        cursor.execute(query, (category_id, *shop_ids, MAX_PRODUCTS))
                    else:
                        placeholders = ",".join(["%s"] * len(shop_ids))
                        query = f"""
                            SELECT 
                                p.product_id as id, 
                                p.name, 
                                p.price, 
                                c.name as category,
                                p.stock 
                            FROM Products p
                            LEFT JOIN Categories c ON p.categoryid = c.categories_id
                            WHERE p.shop_id IN ({placeholders})
                            ORDER BY p.product_id DESC 
                            LIMIT %s
                        """
                        cursor.execute(query, (*shop_ids, MAX_PRODUCTS))
                    
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        pid = row.get('id')
                        name = row.get('name')
                        price = float(row.get('price') or 0)
                        category = row.get('category', 'uncategorized')
                        stock = row.get('stock', 0)
                        img_url = get_product_image_url(pid)
                        
                        products.append({
                            'id': pid,
                            'name': name,
                            'price': price,
                            'stock': stock,
                            'rating': 0,
                            'rating_count': 0,
                            'image': img_url,
                            'category': category
                        })
                        
                except Exception as e2:
                    app.logger.error(f"Fallback query also failed: {e2}")
                    products = []
        else:
            # No shops linked to this customer
            app.logger.warning(f"No shops found for user: {user_email}")
            products = []
        
        # Step 4: Get cart count for current user and selected shop
        userid = session.get("user")
        shopid = session.get("selected_shop_id", 1)
        cart_count = get_cart_count(userid, shopid)
        
        # Close connection
        conn.close()
        
        return render_template('dashboard.html',
                               user=session.get("user"),
                               full_name=session.get("full_name"),
                               cart_count=cart_count,
                               products=products,
                               categories=cats)
                               
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        if conn:
            conn.close()
        return render_template('dashboard.html',
                               user=session.get("user"),
                               full_name=session.get("full_name"),
                               cart_count=0,
                               products=[],
                               categories=[]), 500

@app.route('/send_registration_request', methods=['POST'])
@login_required
def send_registration_request():
    pass

def get_product_image_url(product_id):

    """
    Get the image URL for a product, checking multiple locations:
    1. Database image field
    2. static/uploads/product_{id}.jpg/.jpeg/.png
    3. static/uploads/{id}.jpg/.jpeg/.png
    4. Fallback to logo.png
    """
    if not product_id:
        return url_for('static', filename='logo.png')

    # First, check if image is stored in database
    conn, cursor = get_db()
    try:
        cursor.execute("SELECT image FROM Products WHERE product_id = %s", (product_id,))
        row = cursor.fetchone()
        if row and row.get('image')==None:
            return url_for('static', filename='logo.png')
        if row and row.get('image'):
            # If image field exists in DB, use it
            img_filename = row.get('image')
            # Check if it exists in uploads folder
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            img_path = os.path.join(upload_folder, img_filename)
            if os.path.exists(img_path):
                return url_for('static', filename=f'uploads/{img_filename}')
    except Exception:
        pass
    finally:
        conn.close()

    # If no DB image or file doesn't exist, check for standard naming patterns
    upload_folder = os.path.join(app.root_path, 'static', 'uploads')
    os.makedirs(upload_folder, exist_ok=True)

    # Try different filename patterns
    patterns = [
        f"product_{product_id}.jpg",
        f"product_{product_id}.jpeg",
        f"product_{product_id}.png",
        f"product_{product_id}.JPG",
        f"product_{product_id}.JPEG",
        f"product_{product_id}.PNG",
        f"{product_id}.jpg",
        f"{product_id}.jpeg",
        f"{product_id}.png",
        f"{product_id}.JPG",
        f"{product_id}.JPEG",
        f"{product_id}.PNG",
    ]

    for pattern in patterns:
        img_path = os.path.join(upload_folder, pattern)
        if os.path.exists(img_path):
            return url_for('static', filename=f'uploads/{pattern}')

    # Fallback to default logo
    return url_for('static', filename='logo.png')

@app.route("/admin_dashboard", methods=["GET", "POST"])
@admin_required
def admin_dashboard():

    conn, cursor = get_db()
    userid = session.get("user")
    current_shop = None
    shop_names = []

    try:
        # Ensure we explicitly control transactions (commit/rollback)
        try:
            conn.autocommit = False
        except Exception:
            pass

        # Get all shops for this user
        cursor.execute("SELECT shopid, name FROM Shops WHERE userid = %s ORDER BY name", (userid,))
        shops = cursor.fetchall()
        shop_names = [shop['name'] for shop in shops]

        # Get current shop from POST data or session
        if request.method == "POST":
            current_shop = request.form.get("shop")
        else:
            # On GET, do not auto-select any shop so admin can explicitly choose one
            current_shop = None
            # Also clear any previous selection from the session so login shows no selection
            session.pop('selected_shop_id', None)
            session.pop('selected_shop_name', None)

        # Get shop data if shop is selected
        total_sales = 0
        orders_today = 0
        total_products = 0
        low_stock_items = 0
        orders_list = []

        if current_shop:
            # Get shopid from shop name
            cursor.execute("SELECT shopid FROM Shops WHERE name = %s AND userid = %s", (current_shop, userid))
            shop_result = cursor.fetchone()

            if shop_result:
                shopid = shop_result['shopid']
                session["shopid"] = shopid

                # Get total products
                cursor.execute("SELECT COUNT(*) as count FROM Products WHERE shop_id = %s", (shopid,))
                result = cursor.fetchone()
                total_products = result['count'] if result else 0

                # Get low stock items
                cursor.execute("SELECT COUNT(*) as count FROM Products WHERE shop_id = %s AND stock <= safe_stock", (shopid,))
                result = cursor.fetchone()
                low_stock_items = result['count'] if result else 0

                # Get total sales (only include completed orders)
                try:
                    # accept both 'delivered' and legacy 'completed' as final/sale states;
                    # trim and lower the status to avoid mismatches from whitespace/case
                    cursor.execute("SELECT IFNULL(SUM(total_price),0) as total_sales FROM Orders WHERE shopid = %s AND TRIM(LOWER(COALESCE(status,''))) IN ('delivered','completed')", (shopid,))
                    r = cursor.fetchone()
                    total_sales = float((r or {}).get('total_sales') or 0)
                except Exception:
                    total_sales = 0

                # Orders placed today (completed only)
                try:
                    # count today's orders that are in a final/sale state
                    cursor.execute("SELECT COUNT(*) as orders_today FROM Orders WHERE shopid = %s AND DATE(created_at) = CURDATE() AND TRIM(LOWER(COALESCE(status,''))) IN ('delivered','completed')", (shopid,))
                    r = cursor.fetchone()
                    orders_today = int((r or {}).get('orders_today') or 0)
                except Exception:
                    orders_today = 0

                # Get sample orders (latest 5 regardless of status)
                cursor.execute("""
                    SELECT orderid as id, userid as customer, status, total_price as amount
                    FROM Orders WHERE shopid = %s
                    ORDER BY created_at DESC LIMIT 5
                """, (shopid,))
                orders_list = cursor.fetchall()

        conn.close()

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        shop_names = []

    return render_template('dashboard2.html',
        user=session.get("user"),
        full_name=session.get("full_name"),
        current_shop=current_shop or "No Shop",
        shop_names=shop_names,
        total_sales=total_sales,
        orders_today=orders_today,
        total_products=total_products,
        low_stock_items=low_stock_items,
        orders_list=orders_list
    )

@app.route('/manage-orders')
@admin_required
def manage_orders():
    conn, cursor = get_db()
    """Render the Manage_order.html page for the selected shop (admin only).
    Accepts optional query param `shop_id` to override the session selection.
    """
    # Try query param first, then session
    shop_id = request.args.get('shop_id') or session.get('selected_shop_id')
    if not shop_id:
        flash('Please select a shop first.', 'warning')
        return redirect(url_for('admin_dashboard'))

    try:
        shop_id = int(shop_id)
    except Exception:
        flash('Invalid shop id.', 'error')
        return redirect(url_for('admin_dashboard'))
    # Verify shop belongs to admin
    cursor.execute("SELECT shopid, name FROM Shops WHERE Shopid = %s AND userid = %s", (shop_id, session.get('user')))
    shop = cursor.fetchone()
    if not shop:
        conn.close()
        flash('Shop not found or access denied.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Load recent orders for this shop
    cursor.execute("SELECT orderid, userid, status, total_price, created_at FROM Orders WHERE shopid = %s ORDER BY created_at DESC", (shop_id,))
    orders = cursor.fetchall() or []

    # Fetch items count per order in one query to avoid N+1
    order_ids = [o['orderid'] for o in orders if o.get('orderid')]
    counts = {}
    if order_ids:
        placeholders = ','.join(['%s'] * len(order_ids))
        cursor.execute(f"SELECT orderid, COUNT(*) AS cnt FROM Order_Items WHERE orderid IN ({placeholders}) GROUP BY orderid", tuple(order_ids))
        for r in cursor.fetchall() or []:
            counts[r['orderid']] = r.get('cnt', 0)

    # Normalize fields for template
    for o in orders:
        # store as 'items_count' to avoid colliding with the built-in dict.method `items`
        o['items_count'] = counts.get(o.get('orderid'), 0)
        d = o.get('created_at')
        try:
            o['created_at'] = d.strftime("%Y-%m-%d %H:%M:%S") if d else ''
        except Exception:
            o['created_at'] = str(d) if d else ''

    conn.close()
    return render_template('Manage_order.html', orders=orders, selected_shop_name=shop.get('name'))


@app.route("/register")
@login_required
def register():
    return render_template('register.html')
def random4(length=4):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

@app.route("/products", methods=["GET", "POST"])
@login_required
def products():

    conn, cursor = get_db()
    if request.method == "POST":
        name = request.form.get("name")
        price = request.form.get("price")
        tax = request.form.get("tax")
        stock = request.form.get("stock")
        safe_stock = request.form.get("safe_stock")
        categoryid = request.form.get("categoryid")
        shopid = session.get('selected_shop_id')
        cursor.execute("""
            INSERT INTO Products (name, price, tax, stock, safe_stock, categoryid,shopid,shop_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (name, price, tax, stock, safe_stock, categoryid,shopid,shopid))
        conn.commit()
        conn.close()

        return redirect(url_for("products"))  # refresh after insert

    return render_template("products.html")  # show your UI

@app.route("/api/categories", methods=["GET"])
@login_required
def api_categories():

    conn, cursor = get_db()
    """Fetch categories for the current user's shop"""
    try:
        # For now, fetch all categories (in production, filter by user's shop)
        cursor.execute("SELECT categories_id, name FROM Categories ORDER BY name")
        categories = cursor.fetchall()
        conn.close()
        return jsonify(categories), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

@app.route("/api/export-products", methods=["GET"])
@login_required
def api_export_products():
    conn, cur = get_db()
    """Export all products from the selected shop as JSON"""
    try:
        # Check if user is logged in
        if "user" not in session:
            return jsonify({"success": False, "message": "Please login first"}), 401

        shop_id = session.get("selected_shop_id")
        if not shop_id:
            return jsonify({"success": False, "message": "No shop selected"}), 400
        # Fetch all products with category names for the selected shop
        cur.execute(
            """
            SELECT p.product_id, p.name, p.price, p.tax, p.stock, p.safe_stock, c.name AS category_name
            FROM Products p
            LEFT JOIN Categories c ON p.categoryid = c.categories_id
            WHERE p.shop_id = %s
            ORDER BY p.product_id DESC
            """,
            (shop_id,)
        )

        products = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({"success": True, "products": products}), 200
    except mysql.connector.Error as err:
        return jsonify({"success": False, "message": f"Database error: {err}"}), 500
    except Exception as err:
        return jsonify({"success": False, "message": f"Error: {err}"}), 500

@app.route('/api/products', methods=['GET'])
@login_required
def api_products():
    conn, cur = get_db()
    """Return products as JSON. Optional query param: category (id or name)."""
    try:
        category = request.args.get('category')
        category_id = None
        if category:
            if re.fullmatch(r"\d+", category.strip()):
                category_id = int(category.strip())
            else:
                cur.execute("SELECT categories_id FROM Categories WHERE name = %s LIMIT 1", (category,))
                row = cur.fetchone()
                if row:
                    category_id = row.get('categories_id')

        if category_id:
            cur.execute("SELECT product_id as id, name, image, price,stock,tax ,safe_stock FROM Products WHERE categoryid = %s ORDER BY product_id DESC", (category_id,))
        else:
            cur.execute("SELECT product_id as id, name, image, price,stock,tax ,safe_stock FROM Products ORDER BY product_id DESC")

        rows = cur.fetchall()
        products = []
        for r in rows:
            pid = r.get('id')
            img = r.get('image')
            img_path =f'static/uploads/{img}'
            print(f"Processing product {pid} with image field: {img_path}")
            filename = img_path if img and os.path.exists(os.path.join(app.root_path, img_path)) else None
            if filename:
                img_url = filename
            else:
                img_url = "static/logo.png"

            products.append({
                'id': pid,
                'name': r.get('name'),
                'price': float(r.get('price') or 0),
                'image': img_url,
                'stock': int(r.get('stock') or 0),
                'tax': float(r.get('tax') or 0),
                'safe_stock' : int(r.get('safe_stock') or 0)
            })

        conn.close()
        return jsonify({'success': True, 'products': products}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500



@app.route("/add-products", methods=["POST"])
@login_required
def add_products():
    conn, cur = get_db()
    """API endpoint to save multiple products in bulk with descriptions."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data provided"}), 400

        shopid = session.get("selected_shop_id")
        if not shopid:
            return jsonify({"success": False, "message": "No shop selected. Please select a shop before adding products."}), 400

        saved_count = 0

        for product in data:
            name = product.get("name", "").strip()
            if not name:
                continue  # Skip products without a name

            price = product.get("price", "0.00")
            tax = product.get("tax", "0.00")
            stock = product.get("stock", "0")
            safe_stock = product.get("safe_stock", "0")
            category_input = product.get("categoryid") or product.get("category", "")
            description = product.get("description", "").strip()

            # Parse description lines (support both single field and old format)
            description_lines = []

            # Check for new single description field with line breaks
            if description:
                # Split by newlines and filter out empty lines
                description_lines = [line.strip() for line in description.split('\n') if line.strip()]
            else:
                # Check for old format: description1, description2, etc.
                for i in range(1, 6):
                    desc_key = f"description{i}"
                    if desc_key in product and product[desc_key]:
                        desc_line = product[desc_key].strip()
                        if desc_line:
                            description_lines.append(desc_line)

            # Process category
            categoryid = None
            if category_input:
                category_input = str(category_input).strip()
                if category_input:
                    try:
                        categoryid = int(category_input)
                    except (ValueError, TypeError):
                        # lookup by name for this shop; create if missing
                        cur.execute(
                            "SELECT categories_id FROM Categories WHERE name = %s AND shopid = %s",
                            (category_input, shopid)
                        )
                        cat_row = cur.fetchone()
                        if cat_row:
                            categoryid = cat_row[0] if isinstance(cat_row, tuple) else cat_row.get('categories_id')
                        else:
                            cur.execute(
                                "INSERT INTO Categories (name, shopid, created_at) VALUES (%s, %s, %s)",
                                (category_input, shopid, datetime.now())
                            )
                            conn.commit()
                            categoryid = cur.lastrowid

            # Insert product
            cur.execute(
                """
                INSERT INTO Products (name, price, tax, stock, safe_stock, categoryid, shop_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (name, price, tax, stock, safe_stock, categoryid, shopid)
            )
            product_id = cur.lastrowid

            # Insert descriptions if any
            if description_lines:
                # Ensure we have exactly 5 description slots (pad with empty strings if needed)
                desc_values = description_lines[:5]  # Take up to 5 lines
                desc_values += [''] * (5 - len(desc_values))  # Pad with empty strings if less than 5

                cur.execute(
                    """
                    INSERT INTO product_desc
                    (product_id, description1, description2, description3, description4, description5)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (product_id, *desc_values)
                )

            saved_count += 1

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Successfully saved {saved_count} product(s)",
            "saved": saved_count
        }), 200

    except mysql.connector.Error as err:
        return jsonify({"success": False, "message": f"Database error: {err}"}), 500
    except Exception as err:
        return jsonify({"success": False, "message": f"Error: {err}"}), 500


@app.route('/add_to_cart/<int:product_id>', methods=['GET' , 'POST'])
@login_required
def add_to_cart(product_id):
    conn, cur = get_db()
    """Add product to cart using MySQL tables. Returns JSON with updated cart count."""
    try:
        userid = session.get('user')
        # Determine shop id from the product itself. Fall back to session selection.
        shopid = session.get('selected_shop_id', 1)
        qty = 1

        # Accept form or JSON quantity
        if request.form and request.form.get('quantity'):
            try:
                qty = int(request.form.get('quantity'))
            except Exception:
                qty = 1
        else:
            try:
                body = request.get_json(silent=True) or {}
                if body and body.get('quantity'):
                    qty = int(body.get('quantity'))
            except Exception:
                qty = 1

        cur.execute("SELECT product_id, name, price, shop_id FROM Products WHERE product_id = %s", (product_id,))
        prod = cur.fetchone()
        if not prod:
            conn.close()
            return jsonify({"success": False, "message": "Product not found"}), 404
        # Use the product's shop_id as the cart's shop
        product_shopid = prod.get('shop_id') if prod.get('shop_id') is not None else shopid

        # Get or create cart for user and product's shop
        cur.execute("SELECT cartid FROM Carts WHERE userid = %s AND shopid = %s", (userid, product_shopid))
        cart_row = cur.fetchone()

        if not cart_row:
            # Create new cart
            cur.execute("INSERT INTO Carts (userid, shopid, created_at) VALUES (%s, %s,%s)",
                       (userid, product_shopid, datetime.now()))
            conn.commit()
            cartid = cur.lastrowid
        else:
            cartid = cart_row['cartid']

        # Check if product already in cart
        cur.execute("SELECT quantity FROM Cart_Items WHERE cartid = %s AND product_id = %s",
                   (cartid, product_id))
        item_row = cur.fetchone()

        if item_row:
            # Update existing item quantity
            new_qty = item_row['quantity'] + qty
            cur.execute("UPDATE Cart_Items SET quantity = %s WHERE cartid = %s AND product_id = %s",
                       (new_qty, cartid, product_id))
        else:
            # Insert new cart item
            cur.execute("INSERT INTO Cart_Items (cartid, product_id, quantity) VALUES (%s, %s, %s)",
                       (cartid, product_id, qty))

        conn.commit()

        # Get total cart item count
        cur.execute("SELECT SUM(quantity) as total FROM Cart_Items WHERE cartid = %s", (cartid,))
        result = cur.fetchone()
        cart_count = result['total'] or 0

        conn.close()
        return jsonify({"success": True, "cart_count": cart_count}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/checkout-shop", methods=["POST"])
@login_required
def api_checkout_shop():
    conn, cur = get_db()
    """Checkout (create order) for a specific shop's cart for the current user."""
    try:
        data = request.get_json() or {}
        shop_id = data.get('shop_id')

        userid = session.get('user')
        if not shop_id:
            return jsonify({"success": False, "message": "shop_id is required"}), 400

        # Get cart for user and shop
        cur.execute("SELECT cartid FROM Carts WHERE userid = %s AND shopid = %s", (userid, shop_id))
        cart_row = cur.fetchone()
        if not cart_row:
            conn.close()
            return jsonify({"success": False, "message": "Cart not found for this shop"}), 404

        cartid = cart_row['cartid']

        # Instead of creating an order and clearing the cart at this step,
        # compute totals and return them so the client can redirect to
        # the `place_order` page. Actual order creation and cart clearing
        # will happen only when the user clicks the final Place Order button
        # (/submit-order).
        cur.execute("SELECT ci.product_id, ci.quantity, p.price, p.tax FROM Cart_Items ci JOIN Products p ON ci.product_id = p.product_id WHERE ci.cartid = %s", (cartid,))
        cart_items = cur.fetchall()
        subtotal = 0.0
        tax = 0.0
        for it in cart_items:
            price = float(it.get('price') or 0)
            qty = int(it.get('quantity') or 0)
            product_tax = it.get('tax')
            subtotal += price * qty
            try:
                pct = float(product_tax) if product_tax is not None else 0.0
            except Exception:
                pct = 0.0
            tax += (price * qty) * (pct / 100.0)
        tax = round(tax, 2)
        total = round(subtotal + tax, 2)

        conn.close()
        return jsonify({"success": True, "message": "Ready to checkout", "cart_id": cartid, "subtotal": subtotal, "tax": tax, "total": total}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/add_shop", methods=["GET", "POST"])
@login_required
def add_shop():
    """Display add shop form"""
    return render_template("add_shop.html")

@app.route("/api/shops", methods=["POST"])
@login_required
def api_create_shop():
    conn, cur = get_db()
    """API endpoint to create a new shop"""
    try:
        data = request.get_json()

        if not data or not data.get('name'):
            return jsonify({"success": False, "message": "Shop name is required"}), 400

        shop_name = data.get('name').strip()
        tax_id = data.get('tax_id', None)
        userid = session.get('user')

        if not userid:
            return jsonify({"success": False, "message": "User not authenticated"}), 401

        # Check if shop name already exists for this user
        cur.execute(
            "SELECT * FROM Shops WHERE name = %s AND userid = %s",
            (shop_name, userid)
        )
        existing_shop = cur.fetchone()

        if existing_shop:
            conn.close()
            return jsonify({
                "success": False,
                "message": f"Shop '{shop_name}' already exists"
            }), 400

        # Insert new shop
        cur.execute(
            "INSERT INTO Shops (userid, name, tax_id, created_at) VALUES (%s, %s, %s, %s)",
            (userid, shop_name, tax_id, datetime.now())
        )
        conn.commit()
        shop_id = cur.lastrowid
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Shop '{shop_name}' created successfully!",
            "shop_id": shop_id
        }), 201

    except mysql.connector.Error as err:
        return jsonify({
            "success": False,
            "message": f"Database error: {err}"
        }), 500
    except Exception as err:
        return jsonify({
            "success": False,
            "message": f"Error: {err}"
        }), 500

@app.route("/api/user-shops", methods=["GET"])
@login_required
def api_user_shops():
    conn, cur = get_db()
    """Fetch all shops for the current user"""
    try:
        userid = session.get('user')

        if not userid:
            return jsonify({"success": False, "message": "User not authenticated"}), 401

        # Get all shops for this user
        cur.execute(
            "SELECT shopid, name, tax_id, created_at FROM Shops WHERE userid = %s ORDER BY name",
            (userid,)
        )
        shops = cur.fetchall()
        conn.close()
        return jsonify({
            "success": True,
            "shops": shops,
            "count": len(shops),
            "selected_shop_id": session.get('selected_shop_id'),
            "selected_shop_name": session.get('selected_shop_name')
        }), 200

    except mysql.connector.Error as err:
        return jsonify({"success": False, "message": f"Database error: {err}"}), 500
    except Exception as err:
        return jsonify({"success": False, "message": f"Error: {err}"}), 500

@app.route("/api/select-shop", methods=["POST"])
@login_required
def api_select_shop():
    conn, cur = get_db()
    """Select a shop and store shop_id in session"""
    try:
        data = request.get_json()
        if not data or not data.get('shop_id'):
            return jsonify({"success": False, "message": "Shop ID is required"}), 400
        shop_id = data.get('shop_id')
        userid = session.get('user')
        if not userid:
            return jsonify({"success": False, "message": "User not authenticated"}), 401
        # Verify shop belongs to current user
        cur.execute(
            "SELECT shopid, name, tax_id FROM Shops WHERE shopid = %s AND userid = %s",
            (shop_id, userid)
        )
        shop = cur.fetchone()
        conn.close()
        if not shop:
            return jsonify({"success": False, "message": "Shop not found or access denied"}), 403
        # Clear any previous selection and store the new shop in session
        session.pop('selected_shop_id', None)
        session.pop('selected_shop_name', None)
        session['selected_shop_id'] = shop['shopid']
        session['selected_shop_name'] = shop['name']
        # mark session modified to ensure changes are saved
        session.modified = True
        # Debug log: show selection and session user
        return jsonify({
            "success": True,
            "message": f"Shop '{shop['name']}' selected",
            "shop_id": shop['shopid'],
            "shop_name": shop['name']
        }), 200
    except mysql.connector.Error as err:
        return jsonify({"success": False, "message": f"Database error: {err}"}), 500
    except Exception as err:
        return jsonify({"success": False, "message": f"Error: {err}"}), 500

@app.route("/api/dashboard-stats/<int:shop_id>", methods=["GET"])
@login_required
def api_dashboard_stats(shop_id):
    conn, cur = get_db()
    """Return dashboard KPIs and low-stock lists for the given shop_id."""
    try:

        # Total sales for this shop
        # Count orders whose status is a final/sale state (delivered/completed)
        cur.execute("SELECT IFNULL(SUM(total_price), 0) AS total_sales FROM Orders WHERE shopid = %s AND TRIM(LOWER(COALESCE(status,''))) IN ('delivered','completed')", (shop_id,))
        total_sales = float((cur.fetchone() or {}).get('total_sales') or 0)

        # Orders placed today for this shop (only delivered/completed orders count toward today's sales)
        cur.execute("SELECT COUNT(*) AS orders_today FROM Orders WHERE shopid = %s AND DATE(created_at) = CURDATE() AND TRIM(LOWER(COALESCE(status,''))) IN ('delivered','completed')", (shop_id,))
        orders_today = int((cur.fetchone() or {}).get('orders_today') or 0)

        # Total products for this shop
        cur.execute("SELECT COUNT(*) AS total_products FROM Products WHERE shop_id = %s", (shop_id,))
        total_products = int((cur.fetchone() or {}).get('total_products') or 0)

        # Low stock count
        cur.execute("SELECT COUNT(*) AS low_stock_items FROM Products WHERE shop_id = %s AND stock <= safe_stock", (shop_id,))
        low_stock_items = int((cur.fetchone() or {}).get('low_stock_items') or 0)

        # Recent orders list (limit 5)
        cur.execute("SELECT orderid AS id, status, total_price AS amount, created_at FROM Orders WHERE shopid = %s ORDER BY created_at DESC LIMIT 5", (shop_id,))
        orders_list = cur.fetchall() or []

        # Low stock product list (limit 20)
        cur.execute("SELECT product_id, name, stock, safe_stock FROM Products WHERE shop_id = %s AND stock <= safe_stock ORDER BY stock ASC LIMIT 20", (shop_id,))
        low_stock_list = cur.fetchall() or []

        conn.close()

        return jsonify({
            "success": True,
            "total_sales": total_sales,
            "orders_today": orders_today,
            "total_products": total_products,
            "low_stock_items": low_stock_items,
            "orders_list": orders_list,
            "low_stock_list": low_stock_list
        }), 200
    except Exception as err:
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({"success": False, "message": f"Error: {err}"}), 500


##error
@app.route("/edit_product", methods=["GET", "POST"])
@login_required
def edit_product():
    conn, cursor = get_db()
    """Show edit-product page (GET) and update an existing product (POST)."""
    if request.method == 'GET':
        return render_template('edit_product.html', user=session.get('user'))

    # POST - update product
    try:
        data = request.get_json() or {}
        shop_id = session.get("selected_shop_id")

        if not shop_id:
            return jsonify({"success": False, "message": "No shop selected"}), 400

        product_id = data.get("id")
        if not product_id:
            return jsonify({"success": False, "message": "Product ID required"}), 400

        # Check if product belongs to user's shop
        cursor.execute(
            "SELECT p.product_id FROM Products p WHERE p.product_id = %s AND p.shop_id = %s",
            (product_id, shop_id)
        )
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"success": False, "message": "Product not found"}), 404

        # Resolve category ID
        categoryid = data.get("categoryid")
        if data.get("category_name"):
            cursor.execute(
                "SELECT categories_id FROM Categories WHERE name = %s",
                (data.get("category_name"))
            )
            cat = cursor.fetchone()
            if cat:
                categoryid = cat["categories_id"] if isinstance(cat, dict) else cat[0]
            else:
                # Create new category
                cursor.execute(
                    "INSERT INTO Categories (name, created_at) VALUES (%s, %s)",
                    (data.get("category_name"), datetime.now())
                )
                conn.commit()
                categoryid = cursor.lastrowid

        # Update product
        cursor.execute(
            """UPDATE Products SET
               name = %s, price = %s, tax = %s,
               stock = %s, safe_stock = %s,
               categoryid = %s
               WHERE product_id = %s AND shop_id = %s""",
            (
                data.get("name"),
                float(data.get("price", 0)),
                float(data.get("tax", 0)),
                int(data.get("stock", 0)),
                int(data.get("safe_stock", 0)),
                categoryid,
                product_id,
                shop_id
            )
        )
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"success": True, "message": "Product updated successfully"}), 200
    except mysql.connector.Error as err:
        return jsonify({"success": False, "message": f"Database error: {err}"}), 500
    except Exception as err:
        return jsonify({"success": False, "message": f"Error: {err}"}), 500


@app.route("/api/update-description", methods=["POST"])
@login_required
def update_description():
    """Update product descriptions from single textarea."""
    conn, cursor = get_db()
    try:
        data = request.get_json()
        product_id = data.get("product_id")
        description = data.get("description", "").strip()

        shop_id = session.get("selected_shop_id")
        if not shop_id:
            return jsonify({"success": False, "message": "No shop selected"}), 400

        if not product_id:
            return jsonify({"success": False, "message": "Product ID required"}), 400

        # Verify product belongs to user's shop
        cursor.execute(
            "SELECT product_id FROM Products WHERE product_id = %s AND shop_id = %s",
            (product_id, shop_id)
        )
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"success": False, "message": "Product not found"}), 404

        # Split description into lines
        desc_lines = [line.strip() for line in description.split('\n') if line.strip()]

        # Ensure we have exactly 5 description fields
        desc_values = desc_lines[:5]  # Take up to 5 lines
        desc_values += [''] * (5 - len(desc_values))  # Pad with empty strings

        # Check if description record already exists
        cursor.execute(
            "SELECT product_id FROM product_desc WHERE product_id = %s",
            (product_id,)
        )

        if cursor.fetchone():
            # Update existing description
            cursor.execute(
                """UPDATE product_desc SET
                   description1 = %s, description2 = %s, description3 = %s,
                   description4 = %s, description5 = %s
                   WHERE product_id = %s""",
                (*desc_values, product_id)
            )
        else:
            # Insert new description
            cursor.execute(
                """INSERT INTO product_desc
                   (product_id, description1, description2, description3, description4, description5)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (product_id, *desc_values)
            )

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"success": True, "message": "Description updated successfully"}), 200

    except mysql.connector.Error as err:
        return jsonify({"success": False, "message": f"Database error: {err}"}), 500
    except Exception as err:
        return jsonify({"success": False, "message": f"Error: {err}"}), 500

@app.route("/orders")
@login_required
def orders():
    conn, cur = get_db()
    """Render orders page with recent order items for the current user."""
    userid = session.get('user')
    try:
        cur.execute("""
            SELECT oi.id AS id, oi.orderid AS orderid, oi.product_id, p.name AS product,
                   oi.quantity AS qty, oi.price AS price, o.created_at AS date,
                   o.updated_at, o.status AS status, o.delivered_at as delivery_date
            FROM Order_Items oi
            JOIN Orders o ON oi.orderid = o.orderid
            LEFT JOIN Products p ON oi.product_id = p.product_id
            WHERE o.userid = %s
            ORDER BY o.created_at DESC
        """, (userid,))
        rows = cur.fetchall() or []
        conn.close()

        current_date = datetime.now()
        
        # Process each order row
        for r in rows:
            # Format dates as strings for display
            created_date = r.get('date')
            updated_date = r.get('updated_at')
            delivery_date = r.get('delivery_date')
            
            # Store original datetime objects for calculations
            r['_created_at_obj'] = created_date
            r['_updated_at_obj'] = updated_date
            r['_delivery_date_obj'] = delivery_date
            
            # Format dates for display
            try:
                r['date'] = created_date.strftime("%Y-%m-%d %H:%M:%S") if created_date else ''
                r['updated_at_str'] = updated_date.strftime("%Y-%m-%d %H:%M:%S") if updated_date else ''
                r['delivery_date_str'] = delivery_date.strftime("%Y-%m-%d %H:%M:%S") if delivery_date else ''
            except Exception:
                r['date'] = str(created_date) if created_date else ''
                r['updated_at_str'] = str(updated_date) if updated_date else ''
                r['delivery_date_str'] = str(delivery_date) if delivery_date else ''

            r['price'] = float(r.get('price') or 0)
            r['status'] = (r.get('status') or '').lower()

            # Calculate return eligibility based on delivery_date, NOT updated_at
            r['can_return'] = False
            r['return_until_date'] = None
            
            # Use delivery_date for return eligibility, not updated_at
            if r['status'] == 'delivered' and r['_delivery_date_obj']:
                try:
                    delivered_date = r['_delivery_date_obj']
                    if isinstance(delivered_date, str):
                        delivered_date = datetime.strptime(delivered_date.split('.')[0], "%Y-%m-%d %H:%M:%S")
                    
                    # Make sure delivered_date is timezone-naive for comparison
                    if hasattr(delivered_date, 'tzinfo') and delivered_date.tzinfo is not None:
                        delivered_date = delivered_date.replace(tzinfo=None)
                    
                    days_since_delivery = (current_date - delivered_date).days
                    r['can_return'] = days_since_delivery <= 7

                    # Calculate return until date
                    if r['can_return']:
                        return_until = delivered_date + timedelta(days=7)
                        r['return_until_date'] = return_until.strftime('%Y-%m-%d')
                    else:
                        r['return_until_date'] = 'Return window closed'
                        
                except Exception as e:
                    app.logger.error(f"Error calculating return eligibility: {e}")
                    # Safer fallback - don't show return button if we can't calculate
                    r['can_return'] = False
                    r['return_until_date'] = None

        return render_template('orders.html', 
                             user=session.get('user'), 
                             orders=rows,
                             now=datetime.now,
                             timedelta=timedelta)
    except Exception as e:
        app.logger.exception('Failed to load orders')
        flash('Unable to load your orders at this time.', 'error')
        return render_template('orders.html', 
                             user=session.get('user'), 
                             orders=[],
                             now=datetime.now,
                             timedelta=timedelta)

@app.route('/return/<int:order_item_id>', methods=['POST'])
@login_required
def return_item(order_item_id):
    """Handle return request for an order item"""
    userid = session.get('user')
    conn, cur = get_db()
    
    try:
        # First, verify the order item belongs to the current user and is eligible for return
        cur.execute("""
            SELECT oi.id, o.orderid, o.status, o.delivered_at, o.userid,
                   oi.product_id, oi.quantity, oi.price
            FROM Order_Items oi
            JOIN Orders o ON oi.orderid = o.orderid
            WHERE oi.id = %s AND o.userid = %s
        """, (order_item_id, userid))
        
        order_item = cur.fetchone()
        
        if not order_item:
            flash('Order item not found.', 'error')
            return redirect(url_for('orders'))
        
        # Check if order is delivered and within 7-day return window
        if order_item['status'] != 'delivered':
            flash('Only delivered items can be returned.', 'error')
            return redirect(url_for('orders'))
        
        # Check return window (7 days from delivery)
        if order_item['delivered_at']:
            delivered_date = order_item['delivered_at']
            
            # Handle string or datetime object
            if isinstance(delivered_date, str):
                delivered_date = datetime.strptime(delivered_date.split('.')[0], "%Y-%m-%d %H:%M:%S")
            
            # Calculate days since delivery
            current_time = datetime.now()
            days_since_delivery = (current_time - delivered_date).days
            
            # DEBUG: Print values to see what's happening
            app.logger.info(f"Delivered date: {delivered_date}, Current: {current_time}, Days: {days_since_delivery}")
            
            # Fix: If more than 7 days have passed (8 or more days), block the return
            if days_since_delivery >= 8:  # Changed from > 7 to >= 8
                flash('Return window has expired (7 days from delivery).', 'error')
                return redirect(url_for('orders'))
            
            # Optional: Also check if it's the same day or negative (future delivery - shouldn't happen)
            if days_since_delivery < 0:
                flash('Invalid delivery date.', 'error')
                return redirect(url_for('orders'))
        
        # If we get here, it's within 7 days (0-7 days)
        # Update order status to return_requested
        cur.execute("""
            UPDATE Orders 
            SET status = 'return_requested', 
                updated_at = CURRENT_TIMESTAMP
            WHERE orderid = %s
        """, (order_item['orderid'],))
        
        conn.commit()
        flash('Return request submitted successfully!', 'success')
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error processing return: {e}")
        flash('Failed to process return request. Please try again.', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('orders'))

@app.route("/return-status/<int:order_item_id>")
@login_required
def return_status(order_item_id):
    """Show detailed return status for an order item."""
    userid = session.get('user')

    try:
        conn, cur = get_db()

        # Get order details with product info
        cur.execute("""
            SELECT
                oi.id,
                oi.orderid,
                oi.product_id,
                p.name AS product_name,
                oi.quantity,
                oi.price,
                o.status,
                o.created_at AS order_date,
                o.updated_at AS delivered_date,
                o.userid,
                (
                    SELECT updated_at
                    FROM Orders
                    WHERE orderid = o.orderid
                    AND status = 'return_requested'
                    LIMIT 1
                ) AS return_requested_date
            FROM Order_Items oi
            JOIN Orders o ON oi.orderid = o.orderid
            LEFT JOIN Products p ON oi.product_id = p.product_id
            WHERE oi.id = %s AND o.userid = %s
        """, (order_item_id, userid))

        order_item = cur.fetchone()
        conn.close()

        if not order_item:
            flash('Order item not found.', 'error')
            return redirect('/orders')

        # Process dates
        if order_item.get('order_date'):
            order_item['order_date'] = order_item['order_date'].strftime("%Y-%m-%d %H:%M:%S") \
                if hasattr(order_item['order_date'], 'strftime') else str(order_item['order_date'])

        if order_item.get('delivered_date'):
            order_item['delivered_date'] = order_item['delivered_date'].strftime("%Y-%m-%d %H:%M:%S") \
                if hasattr(order_item['delivered_date'], 'strftime') else str(order_item['delivered_date'])

        if order_item.get('return_requested_date'):
            order_item['return_requested_date'] = order_item['return_requested_date'].strftime("%Y-%m-%d %H:%M:%S") \
                if hasattr(order_item['return_requested_date'], 'strftime') else str(order_item['return_requested_date'])

        # Calculate refund amount and timeline
        from datetime import datetime, timedelta

        refund_info = {
            'eligible': False,
            'refund_amount': 0,
            'refund_method': 'Original Payment Method',
            'estimated_timeline': '5-7 business days',
            'return_by_date': '',
            'pickup_scheduled': False
        }

        if order_item.get('status') == 'return_requested':
            refund_info['eligible'] = True
            refund_info['refund_amount'] = float(order_item.get('price', 0)) * int(order_item.get('quantity', 1))

            # Calculate return by date (14 days from request)
            if order_item.get('return_requested_date'):
                try:
                    return_date = datetime.strptime(order_item['return_requested_date'].split('.')[0], "%Y-%m-%d %H:%M:%S")
                    return_by = return_date + timedelta(days=14)
                    refund_info['return_by_date'] = return_by.strftime("%B %d, %Y")
                except:
                    refund_info['return_by_date'] = 'Within 14 days'

        return render_template('return_status.html',
                             order_item=order_item,
                             refund_info=refund_info,
                             user=session.get('user'))

    except Exception as e:
        app.logger.exception('Failed to load return status')
        flash('Unable to load return details.', 'error')
        return redirect('/orders')

@app.route('/cancel/<int:item_id>', methods=['POST'])
@login_required
def cancel_order(item_id):
    conn, cur = get_db()
    """Cancel the order associated with the given Order_Items.id (if owned by user).
    This matches the current template which posts the Order_Items id.
    """
    userid = session.get('user')
    try:

        # Find the parent order and verify ownership
        cur.execute(
            "SELECT oi.orderid AS orderid, o.userid AS userid FROM Order_Items oi JOIN Orders o ON oi.orderid = o.orderid WHERE oi.id = %s",
            (item_id,)
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            flash('Order not found.', 'error')
            return redirect(url_for('orders'))

        if row.get('userid') != userid:
            conn.close()
            flash('You are not authorized to cancel this order.', 'error')
            return redirect(url_for('orders'))

        orderid = row.get('orderid')

        # Update order status to cancelled
        cur.execute("UPDATE Orders SET status = %s WHERE orderid = %s", ('cancelled', orderid))
        conn.commit()
        conn.close()

        flash(f'Order #{orderid} cancelled.', 'success')
        return redirect(url_for('orders'))
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        app.logger.exception('Failed to cancel order')
        flash('Unable to cancel order at this time.', 'error')
        return redirect(url_for('orders'))

def get_cart_count(userid, shopid=None):
    conn, cur = get_db()
    """Get total cart item count from MySQL for user/shop."""
    try:
        if not shopid:
            shopid = session.get('selected_shop_id', 1)
        cur.execute("SELECT SUM(ci.quantity) as total FROM Cart_Items ci JOIN Carts c ON ci.cartid = c.cartid WHERE c.userid = %s",
                   (userid,))
        result = cur.fetchone()
        conn.close()
        return result['total'] or 0 if result else 0
    except Exception:
        return 0

@app.route("/api/cart-count", methods=['GET'])
@login_required
def api_cart_count():
    """Get current cart count from database."""
    try:
        userid = session.get('user')
        shopid = session.get('selected_shop_id', 1)
        count = get_cart_count(userid, shopid)
        return jsonify({"success": True, "cart_count": count}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
@app.route("/api/view-cart", methods=['GET'])
@login_required
def api_view_cart():
    conn, cur = get_db()
    """Fetch all cart items for the user with product details."""
    try:
        app.logger.debug(f"api_view_cart session user={session.get('user')}")
        userid = session.get('user')

        # Updated query to include product image
        cur.execute("""
            SELECT
                ci.product_id,
                p.name,
                p.price,
                p.tax,
                p.image,
                ci.quantity,
                c.shopid AS shop_id,
                s.name AS shop_name
            FROM Cart_Items ci
            JOIN Carts c ON ci.cartid = c.cartid
            JOIN Products p ON ci.product_id = p.product_id
            LEFT JOIN Shops s ON c.shopid = s.shopid
            WHERE c.userid = %s
            ORDER BY c.shopid, ci.product_id DESC
        """, (userid,))

        rows = cur.fetchall()
        items = []
        for row in rows:
            # Extract image from row
            img = row.get('image')

            # Construct image URL
            if img:
                img_url = url_for('static', filename=f"uploads/{img}", _external=True)
            else:
                img_url = url_for('static', filename='logo.png', _external=True)

            items.append({
                'product_id': row['product_id'],
                'name': row['name'],
                'price': float(row['price']) if row.get('price') is not None else 0.0,
                'tax': float(row['tax']) if row.get('tax') is not None else 0.0,
                'image': img_url,  # Now includes the actual image URL
                'quantity': row['quantity'],
                'shop_id': row.get('shop_id'),
                'shop_name': row.get('shop_name') or 'Shop'
            })

        conn.close()
        return jsonify({"success": True, "items": items}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/update-cart-item", methods=['POST'])
@login_required
def api_update_cart_item():
    conn, cur = get_db()
    """Update quantity of a cart item."""
    try:
        data = request.get_json() or {}
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)

        if not product_id:
            return jsonify({"success": False, "message": "Product ID required"}), 400

        try:
            quantity = int(quantity)
            if quantity < 1:
                raise ValueError("Quantity must be >= 1")
        except (ValueError, TypeError):
            return jsonify({"success": False, "message": "Invalid quantity"}), 400

        userid = session.get('user')

        # Determine shop from product if provided, otherwise fall back to session
        product_shopid = None
        if product_id:
            try:
                cur.execute("SELECT shop_id FROM Products WHERE product_id = %s", (product_id,))
                p = cur.fetchone()
                if p:
                    product_shopid = p.get('shop_id')
            except Exception:
                product_shopid = None

        shopid = product_shopid or session.get('selected_shop_id', 1)

        # Get cart for user and resolved shop
        cur.execute("SELECT cartid FROM Carts WHERE userid = %s AND shopid = %s", (userid, shopid))
        cart_row = cur.fetchone()

        if not cart_row:
            conn.close()
            return jsonify({"success": False, "message": "Cart not found"}), 404

        cartid = cart_row['cartid']

        # Update quantity
        cur.execute("UPDATE Cart_Items SET quantity = %s WHERE cartid = %s AND product_id = %s",
                   (quantity, cartid, product_id))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Quantity updated"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/remove-cart-item", methods=['POST'])
@login_required
def api_remove_cart_item():
    conn, cur = get_db()
    """Remove an item from cart."""
    try:
        data = request.get_json() or {}
        product_id = data.get('product_id')

        if not product_id:
            return jsonify({"success": False, "message": "Product ID required"}), 400

        userid = session.get('user')

        # Determine shop from product if provided, otherwise fall back to session
        product_shopid = None
        if product_id:
            try:
                cur.execute("SELECT shop_id FROM Products WHERE product_id = %s", (product_id,))
                p = cur.fetchone()
                if p:
                    product_shopid = p.get('shop_id')
            except Exception:
                product_shopid = None

        shopid = product_shopid or session.get('selected_shop_id', 1)

        # Get cart for user and resolved shop
        cur.execute("SELECT cartid FROM Carts WHERE userid = %s AND shopid = %s", (userid, shopid))
        cart_row = cur.fetchone()

        if not cart_row:
            conn.close()
            return jsonify({"success": False, "message": "Cart not found"}), 404

        cartid = cart_row['cartid']

        # Delete item
        cur.execute("DELETE FROM Cart_Items WHERE cartid = %s AND product_id = %s",
                   (cartid, product_id))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Item removed"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/checkout", methods=['POST'])
@login_required
def api_checkout():
    conn, cur = get_db()
    """Create an order from cart and clear the cart."""
    try:
        data = request.get_json() or {}
        tax_amount = data.get('tax_amount', 0)

        userid = session.get('user')

        # Find a cart for this user that currently has items; prefer the cart with items
        cur.execute(
            "SELECT c.cartid, c.shopid FROM Carts c JOIN Cart_Items ci ON c.cartid = ci.cartid WHERE c.userid = %s LIMIT 1",
            (userid,)
        )
        cart_row = cur.fetchone()

        if not cart_row:
            conn.close()
            return jsonify({"success": False, "message": "Cart not found"}), 404

        cartid = cart_row['cartid']
        shopid = cart_row.get('shopid')

        # Do NOT create the order or clear the cart here. This endpoint
        # will validate and return computed totals so the client can
        # redirect the user to the `place_order` page. The final order
        # creation and cart clearing happen only in `/submit-order`
        cur.execute("SELECT ci.product_id, ci.quantity, p.price, p.tax FROM Cart_Items ci JOIN Products p ON ci.product_id = p.product_id WHERE ci.cartid = %s and shop_id = %s", (cartid,shopid))
        cart_items = cur.fetchall()
        subtotal = 0.0
        tax_amount = 0.0
        for it in cart_items:
            price = float(it.get('price') or 0)
            qty = int(it.get('quantity') or 0)
            product_tax = it.get('tax')
            subtotal += price * qty
            try:
                pct = float(product_tax) if product_tax is not None else 0.0
            except Exception:
                pct = 0.0
            tax_amount += (price * qty) * (pct / 100.0)
        tax_amount = round(tax_amount, 2)
        total = round(subtotal + tax_amount, 2)

        conn.close()

        return jsonify({
            "success": True,
            "message": "Proceed to place order",
            "cart_id": cartid,
            "subtotal": subtotal,
            "tax_amount": tax_amount,
            "total": total
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/order")
@login_required
def my_orders():
    conn, cur = get_db()
    userid = session.get('user')
    shopid = session.get('selected_shop_id', 1)
    cur.execute("""
        SELECT orderid, total_price, tax_amount, status, created_at
        FROM Orders
        WHERE userid = %s AND shopid = %s
        ORDER BY created_at DESC
    """, (userid, shopid))
    return render_template("my_orders.html" , full_name = session.get("fulll_name"))

@app.route("/view_cart")
@login_required
def view_cart():
    return render_template('view_cart.html', user=session.get("user"))


@app.route('/place_order')
@login_required
def place_order():
    conn, cur = get_db()
    """Render place_order page with server-calculated totals for a shop or the user's cart."""
    userid = session.get('user')
    shop_id = request.args.get('shop_id')

    # Try to load cart items for the user and shop; if not present,
    # fall back to any totals provided via query params so the page
    # can be shown when redirected from checkout.

    cart_row = None
    if shop_id:
        try:
            cur.execute("SELECT cartid FROM Carts WHERE userid = %s AND shopid = %s", (userid, shop_id))
            cart_row = cur.fetchone()
        except Exception:
            cart_row = None
    if not cart_row:
        try:
            cur.execute("SELECT c.cartid, c.shopid FROM Carts c JOIN Cart_Items ci ON c.cartid = ci.cartid WHERE c.userid = %s LIMIT 1", (userid,))
            cart_row = cur.fetchone()
        except Exception:
            cart_row = None

    items = []
    subtotal = 0.0
    tax_amount = 0.0

    if cart_row:
        cartid = cart_row['cartid']
        cur.execute("SELECT ci.product_id, ci.quantity, p.name, p.price, p.tax FROM Cart_Items ci JOIN Products p ON ci.product_id = p.product_id WHERE ci.cartid = %s", (cartid,))
        items = cur.fetchall() or []

        for it in items:
            price = float(it.get('price') or 0)
            qty = int(it.get('quantity') or 0)
            product_tax = it.get('tax')
            subtotal += price * qty
            try:
                pct = float(product_tax) if product_tax is not None else 0.0
            except Exception:
                pct = 0.0
            tax_amount += (price * qty) * (pct / 100.0)

        tax_amount = round(tax_amount, 2)
        total = round(subtotal + tax_amount, 2)
    else:
        # No cart found; attempt to use URL-provided totals
        try:
            subtotal = float(request.args.get('subtotal') or 0)
        except Exception:
            subtotal = 0.0
        try:
            tax_amount = float(request.args.get('tax') or request.args.get('tax_amount') or 0)
        except Exception:
            tax_amount = 0.0
        try:
            total = float(request.args.get('total') or request.args.get('total_amount') or (subtotal + tax_amount))
        except Exception:
            total = round(subtotal + tax_amount, 2)

    conn.close()

    return render_template('place_order.html', cart_items=items, order_subtotal=subtotal, order_tax=tax_amount, order_total=total, full_name=session.get('full_name'))



@app.route('/api/create-order', methods=['POST'])
@login_required
def api_create_order():
    conn, cur = get_db()
    """Create an order from the user's cart for the provided shop (or the cart found).
    Expects JSON with contact/address fields and optionally `shop_id`.
    """
    try:
        data = request.get_json() or {}
        userid = session.get('user')
        if not userid:
            return jsonify({"success": False, "message": "Not authenticated"}), 401

        shop_id = data.get('shop_id')


        # If shop_id provided, find that cart; otherwise pick any cart with items
        if shop_id:
            cur.execute("SELECT cartid FROM Carts WHERE userid = %s AND shopid = %s", (userid, shop_id))
            cart_row = cur.fetchone()
        else:
            cur.execute("SELECT c.cartid, c.shopid FROM Carts c JOIN Cart_Items ci ON c.cartid = ci.cartid WHERE c.userid = %s LIMIT 1", (userid,))
            cart_row = cur.fetchone()

        if not cart_row:
            conn.close()
            return jsonify({"success": False, "message": "Cart not found"}), 404

        cartid = cart_row['cartid']
        shopid = cart_row.get('shopid')

        # Fetch cart items (include product tax)
        cur.execute("SELECT ci.product_id, ci.quantity, p.price, p.tax FROM Cart_Items ci JOIN Products p ON ci.product_id = p.product_id WHERE ci.cartid = %s", (cartid,))
        items = cur.fetchall()
        if not items:
            conn.close()
            return jsonify({"success": False, "message": "Cart is empty"}), 400

        # Compute totals server-side using per-product tax (percent stored in p.tax)
        subtotal = 0.0
        tax_amount = 0.0
        for it in items:
            price = float(it.get('price') or 0)
            qty = int(it.get('quantity') or 0)
            product_tax = it.get('tax')
            subtotal += price * qty
            try:
                pct = float(product_tax) if product_tax is not None else 0.0
            except Exception:
                pct = 0.0
            tax_amount += (price * qty) * (pct / 100.0)
        tax_amount = round(tax_amount, 2)
        total_amount = round(subtotal + tax_amount, 2)

        # Create order (align with submit_order schema)
        cur.execute("INSERT INTO Orders (userid, shopid, total_price, status, created_at) VALUES (%s, %s, %s, %s, %s)", (userid, shopid, total_amount, 'pending', datetime.now()))
        order_id = cur.lastrowid

        # Insert order items
        for item in items:
            cur.execute("INSERT INTO Order_Items (orderid, product_id, quantity, price) VALUES (%s, %s, %s, %s)", (order_id, item['product_id'], item['quantity'], item['price']))

        # Insert order_descriptions if provided
        try:
            phone = data.get('phone')
            street = data.get('street_address') or data.get('street') or data.get('address') or ''
            city = data.get('city') or ''
            state = data.get('state_province') or data.get('state') or ''
            zip_code = data.get('zipcode') or data.get('zip_code') or ''
            country = data.get('country') or ''
            # Insert order description referencing the created order via `order_id` column (try both schemas)
            try:
                cur.execute(
                    "INSERT INTO order_descriptions (orderid, userid, shopid, phone, street, city, state, zip_code, country, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (order_id, userid, shopid, phone or '', street or '', city or '', state or '', zip_code or '', country or '', datetime.now())
                )
            except mysql.connector.Error:
                # Fallback to legacy column name if present
                try:
                    cur.execute(
                        "INSERT INTO order_descriptions (orderid, userid, shopid, phone, street, city, state, zip_code, country, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (order_id, userid, shopid, phone or '', street or '', city or '', state or '', zip_code or '', country or '', datetime.now())
                    )
                except Exception:
                    # swallow; not critical
                    pass
        except Exception:
            pass

        # Clear cart items
        cur.execute("DELETE FROM Cart_Items WHERE cartid = %s", (cartid,))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Order created", "order_id": order_id, "total": total_amount}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/update-order-status', methods=['POST'])
@admin_required
def api_update_order_status():
    conn, cur = get_db()
    """Update an order status. When transitioning to 'delivered' decrement product stock.
    When transitioning from 'delivered' to another status, restore stock quantities.
    Expects JSON: { order_id: <id>, status: <new_status> }
    """
    try:
        data = request.get_json() or {}
        order_id = data.get('order_id') or data.get('orderid') or data.get('id')
        new_status = (data.get('status') or '').strip().lower()

        if not order_id or not new_status:
            conn.close()
            return jsonify({'success': False, 'message': 'order_id and status are required'}), 400

        # Load existing order
        cur.execute("SELECT orderid, status, shopid FROM Orders WHERE orderid = %s", (order_id,))
        order = cur.fetchone()

        if not order:
            conn.close()
            return jsonify({'success': False, 'message': 'Order not found'}), 404

        prev_status = (order.get('status') or '').lower()

        if prev_status == new_status:
            conn.close()
            return jsonify({'success': True, 'message': 'No status change'}), 200

        shopid = order.get('shopid')

        # Fetch order items - check the actual column names in your Order_Items table
        # Based on your Orders table, it's likely orderid (not order_id)
        cur.execute("SELECT product_id, quantity FROM Order_Items WHERE orderid = %s", (order_id,))
        items = cur.fetchall() or []
        # Start transaction
        try:
            current_time  = datetime.now()
            # Update order status
            cur.execute("UPDATE Orders SET status = %s WHERE orderid = %s", (new_status, order_id))
            if prev_status != 'delivered' and new_status == 'delivered':
                cur.execute("update orders set delivered_at = %s where orderid  = %s",(current_time,order_id))

            # If moving to 'delivered' from non-delivered => subtract stock
            if prev_status != 'delivered' and new_status == 'delivered':
                for it in items:
                    pid = it.get('product_id')
                    qty = int(it.get('quantity') or 0)
                    if not pid or qty <= 0:
                        continue
                    cur.execute("UPDATE Products SET stock = GREATEST(0, stock - %s) WHERE product_id = %s AND shop_id = %s", (qty, pid, shopid))

            # If moving from 'delivered' to non-delivered => restore stock
            if prev_status == 'delivered' and new_status != 'delivered':
                for it in items:
                    pid = it.get('product_id')
                    qty = int(it.get('quantity') or 0)
                    if not pid or qty <= 0:
                        continue
                    cur.execute("UPDATE Products SET stock = stock + %s WHERE product_id = %s AND shop_id = %s", (qty, pid, shopid))

            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Status updated successfully'}), 200
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            conn.close()
            return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500

    except Exception as e:
        if 'conn' in locals():
            conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/submit-order', methods=["GET",'POST'])
@login_required
def submit_order():
    conn, cur = get_db()
    """Handle form POST from place_order page; create order, address, clear cart, flash and redirect."""
    try:
        userid = session.get('user')
        if not userid:
            flash('Please login to place an order.', 'error')
            return redirect(url_for('login'))

        form = request.form
        shop_id = form.get('shop_id')


        try:
            # Try reading JSON payload (optional)
            payload = request.get_json(silent=True) or {}
            items = []
            cart_used = False

            # Fetch cart
            if shop_id:
                cur.execute("SELECT cartid FROM Carts WHERE userid = %s AND shopid = %s",
                            (userid, shop_id))
                cart_row = cur.fetchone()
            else:
                cur.execute(
                    "SELECT c.cartid, c.shopid FROM Carts c "
                    "JOIN Cart_Items ci ON c.cartid = ci.cartid "
                    "WHERE c.userid = %s LIMIT 1", (userid,)
                )
                cart_row = cur.fetchone()

            # If cart found → load items
            if cart_row:
                cartid = cart_row['cartid']
                shop_id = cart_row.get('shopid')

                cur.execute("""
                    SELECT ci.product_id, ci.quantity, p.price, p.tax
                    FROM Cart_Items ci
                    JOIN Products p ON ci.product_id = p.product_id
                    WHERE ci.cartid = %s
                """, (cartid,))
                items = cur.fetchall() or []
                cart_used = True

            # If payload items used
            if not items:
                provided_items = payload.get('items')
                if provided_items:
                    prod_ids = [int(x.get('product_id')) for x in provided_items]
                    if prod_ids:
                        placeholders = ','.join(['%s'] * len(prod_ids))
                        cur.execute(
                            f"SELECT product_id, price, tax FROM Products WHERE product_id IN ({placeholders})",
                            tuple(prod_ids)
                        )
                        prod_map = {r['product_id']: r for r in cur.fetchall()}

                        for pi in provided_items:
                            pid = int(pi.get('product_id'))
                            qty = int(pi.get('quantity') or 1)
                            if pid in prod_map:
                                pinfo = prod_map[pid]
                                items.append({
                                    'product_id': pid,
                                    'quantity': qty,
                                    'price': pinfo['price'],
                                    'tax': pinfo['tax']
                                })

            # No items → reject
            if not items:
                conn.close()
                flash('Your cart is empty or no products provided.', 'error')
                return redirect(url_for('view_cart'))

            # Calculate totals
            subtotal = 0.0
            tax_amount = 0.0

            for it in items:
                price = float(it['price'])
                qty = int(it['quantity'])
                tax = float(it['tax'] or 0)

                subtotal += price * qty
                tax_amount += (price * qty) * (tax / 100.0)

            tax_amount = round(tax_amount, 2)
            total_amount = round(subtotal + tax_amount, 2)
            # DEBUG: log the exact payload we're about to insert into DB
            try:
                order_debug = {
                    'userid': userid,
                    'shopid': shop_id,
                    'cart_used': cart_used,
                    'items_count': len(items),
                    'items': items,
                    'subtotal': subtotal,
                    'tax_amount': tax_amount,
                    'total_amount': total_amount,
                    'form_phone': form.get('phone'),
                    'form_street': form.get('street') or form.get('address')
                }
                app.logger.debug('ORDER_INSERT DEBUG: ' + json.dumps(order_debug, default=str))
            except Exception:
                app.logger.exception('Failed to serialize order_debug')

            # Use the connection default transaction behavior (avoid start_transaction() error)
            # Insert tax_amount and status to align with the live `orders` schema
            cur.execute("""
                INSERT INTO Orders (userid, shopid, total_price, tax_amount, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (userid, shop_id, total_amount, tax_amount, 'pending', datetime.now()))

            order_id = cur.lastrowid

            # Insert Order_Items: try to populate both `orderid` and `order_id` when available,
            # otherwise fall back to the older single-column insert.
            for item in items:
                try:
                    cur.execute("""
                        INSERT INTO Order_Items (orderid, order_id, product_id, quantity, price)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (order_id, order_id, item['product_id'], item['quantity'], item['price']))
                except mysql.connector.Error:
                    cur.execute("""
                        INSERT INTO Order_Items (orderid, product_id, quantity, price)
                        VALUES (%s, %s, %s, %s)
                    """, (order_id, item['product_id'], item['quantity'], item['price']))

            # Prepare contact/address fields (prefer JSON payload values for AJAX submissions).
            try:
                phone = (payload.get('phone') if isinstance(payload, dict) else None) or form.get('phone') or ''
                street = (payload.get('street') if isinstance(payload, dict) else None) or form.get('street') or form.get('address') or (payload.get('address') if isinstance(payload, dict) else '')
                city = (payload.get('city') if isinstance(payload, dict) else None) or form.get('city') or ''
                state = (payload.get('state') if isinstance(payload, dict) else None) or form.get('state') or ''
                zip_code = (payload.get('zipcode') if isinstance(payload, dict) else None) or (payload.get('zip_code') if isinstance(payload, dict) else None) or form.get('zipcode') or form.get('zip_code') or ''
                country = (payload.get('country') if isinstance(payload, dict) else None) or form.get('country') or ''

                # Try inserting description using `order_id` FK; fallback to legacy `orderid` column.
                try:
                    cur.execute("""
                        INSERT INTO order_descriptions
                        (orderid, userid, shopid, phone, street, city, state, zip_code, country, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (order_id, userid, shop_id, phone, street, city, state, zip_code, country, datetime.now()))
                except mysql.connector.Error:
                    try:
                        cur.execute("""
                            INSERT INTO order_descriptions
                            (orderid, userid, shopid, phone, street, city, state, zip_code, country, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (order_id, userid, shop_id, phone, street, city, state, zip_code, country, datetime.now()))
                    except Exception:
                        app.logger.exception('order_descriptions insert failed')
            except Exception:
                app.logger.exception('order_descriptions preparation failed')

            if cart_used:
                cur.execute("DELETE FROM Cart_Items WHERE cartid = %s", (cartid,))

            conn.commit()
            conn.close()

            is_ajax = request.is_json or \
                request.headers.get('X-Requested-With') == 'XMLHttpRequest'

            if is_ajax:
                return jsonify({"success": True, "order_id": order_id, "total": total_amount}), 200

            flash(f"Order #{order_id} placed successfully!", 'success')
            return redirect(url_for('orders'))

        except Exception as e:
            # Log full traceback to file so we can inspect SQL/DB errors
            app.logger.exception('submit_order: error during transaction')
            try:
                conn.rollback()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

            is_ajax = request.is_json or \
                request.headers.get('X-Requested-With') == 'XMLHttpRequest'

            if is_ajax:
                return jsonify({"success": False, "message": str(e)}), 500

            flash(f"Error placing order: {e}", 'error')
            return redirect(url_for('place_order'))

    except Exception as e:
        # Log outer exceptions too
        app.logger.exception('submit_order: outer exception')
        flash(f"Error placing order: {e}", 'error')
        return redirect(url_for('place_order'))


@app.route("/inventory")
@login_required
def inventory():
    return render_template('inventory.html', user=session.get("user"))

@app.route("/reports")
@login_required
def reports():
    return render_template('reports.html', user=session.get("user"))

@app.route("/settings")
@login_required
def settings():
    return render_template('settings.html', user=session.get("user"))


@app.before_request
def log_request_info():
    try:
        app.logger.debug(f"REQ {request.method} {request.path} from {request.remote_addr}")
        if request.method in ('POST', 'PUT', 'PATCH'):
            # avoid logging raw passwords, but log JSON body keys for debugging
            try:
                body = request.get_json(silent=True)
                if body:
                    safe_body = {k: ('<omitted>' if 'password' in k.lower() else v) for k, v in body.items()}
                    app.logger.debug(f"Request JSON: {safe_body}")
            except Exception:
                pass
    except Exception:
        pass


@app.errorhandler(Exception)
def handle_uncaught_exception(e):
    # If running with debug mode, re-raise so Werkzeug shows the interactive debugger
    if app.debug:
        raise e

    # Otherwise, log full traceback and return a safe JSON or redirect
    tb = traceback.format_exc()
    app.logger.error(f"Unhandled exception: {e}\n{tb}")
    # For JSON requests return JSON error
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in (request.headers.get('Accept') or ''):
        return jsonify({"success": False, "message": "Internal server error"}), 500
    # For normal requests, flash and redirect back to place_order if available
    try:
        flash('Internal server error. The error has been logged.', 'error')
        return redirect(request.referrer or url_for('dashboard'))
    except Exception:
        return jsonify({"success": False, "message": "Internal server error"}), 500

@app.route('/invoice')
@login_required
def invoice():

    conn, cursor = get_db()
    print("Invoice route started")
    try:
        order_id = request.args.get('order_id', type=int)
        print("Received order_id:", order_id)
        print("Database connected")

        # Fetch order
        cursor.execute("SELECT * FROM Orders WHERE orderid = %s", (order_id,))
        order = cursor.fetchone()
        print("Order fetched:", order)

        # Fetch items
        cursor.execute("""
            SELECT oi.*, p.name
            FROM Order_Items oi
            JOIN Products p ON p.product_id = oi.product_id
            WHERE oi.orderid = %s
        """, (order_id,))
        items = cursor.fetchall()

        cursor.execute("SELECT * FROM order_descriptions WHERE orderid=%s", (order_id,))
        shipping = cursor.fetchone()

        return render_template("invoicee.html", order=order, items=items, shipping=shipping )

    except Exception as e:
        print("INVOICE ERROR:", e)
        return f"Error: {str(e)}", 500

    finally:
        try:
            cursor.close()
        except:
            pass


@app.route('/favicon.ico')
def favicon():
    return '', 200, {'Content-Type': 'image/x-icon'}

@app.route('/api/upload-product-image', methods=['POST'])
@login_required
def upload_product_image():

    """Handle product image uploads and save as product_id.jpg/png in static/uploads"""
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "message": "No image file provided"}), 400

        file = request.files['image']

        if file.filename == '':
            return jsonify({"success": False, "message": "No selected file"}), 400

        product_id = request.form.get('product_id')
        if not product_id:
            return jsonify({"success": False, "message": "Product ID required"}), 400

        # Verify product belongs to user's shop
        conn, cursor = get_db()
        shop_id = session.get("selected_shop_id")

        cursor.execute(
            "SELECT product_id FROM Products WHERE product_id = %s AND shop_id = %s",
            (product_id, shop_id)
        )
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"success": False, "message": "Product not found or unauthorized"}), 404

        # Check if file is an image
        if not file.content_type.startswith('image/'):
            return jsonify({"success": False, "message": "File must be an image"}), 400

        # Create uploads directory if it doesn't exist
        upload_folder = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)

        # Get file extension
        filename = file.filename
        ext = os.path.splitext(filename)[1].lower()

        # Generate filename: product_<id>.<ext>
        # Keep only .jpg, .jpeg, .png extensions
        if ext not in ['.jpg', '.jpeg', '.png']:
            ext = '.jpg'  # default to jpg

        new_filename = f"product_{product_id}{ext}"
        save_path = os.path.join(upload_folder, new_filename)

        # Save the file
        cleanup_product_images(product_id)
        file.save(save_path)

        # Update product record in database (optional - store filename in DB)
        try:
            cursor.execute(
                "UPDATE Products SET image = %s WHERE product_id = %s",
                (new_filename, product_id)
            )
            conn.commit()
        except Exception as db_err:
            # Even if DB update fails, we still have the image file
            print(f"Database update warning: {db_err}")

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Image uploaded successfully as {new_filename}",
            "filename": new_filename
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Error uploading image: {str(e)}"}), 500


def cleanup_product_images(product_id):
    """Remove old image files for a product before uploading new one"""
    upload_folder = os.path.join(app.root_path, 'static', 'uploads')
    extensions = ['.jpg', '.jpeg', '.png', '.JPG', '.JPEG', '.PNG']

    for ext in extensions:
        old_file = os.path.join(upload_folder, f"product_{product_id}{ext}")
        old_file2 = os.path.join(upload_folder, f"{product_id}{ext}")

        for filepath in [old_file, old_file2]:
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    print(f"Removed old image: {filepath}")
                except Exception as e:
                    print(f"Error removing {filepath}: {e}")



@app.route('/product_description/<int:product_id>')
@login_required
def product_description(product_id):

    # Get user ID from session
    user_id = session.get("user")  
    conn, cursor = get_db()
    # Fetch product details with ALL fields
    try:
        shop_ids = session.get("shop_ids", [])
        if not shop_ids:
            return render_template('dashboard.html')
    except Exception as e:
        print(f"Error accessing shop_ids from session: {e}")

    cursor.execute("""
        SELECT p.product_id, p.name, p.price, p.tax, p.stock,p.categoryid,
        pd.description1, pd.description2, pd.description3, pd.description4, pd.description5,
        s.name as shop_name,s.shopid
        FROM Products p LEFT JOIN product_desc pd ON p.product_id = pd.product_id
        JOIN Shops s ON p.shop_id = s.shopid WHERE p.product_id = %s""", (product_id,))
    product = cursor.fetchone()

    if not product:
        return render_template('product_description.html',user=None,product=None,
                             related_products=[],cart_count=0,category_name="",product_image_url="")
    # Create image URL
    cursor.execute("SELECT image FROM Products WHERE product_id = %s", (product_id,))
    image_result = cursor.fetchone()
    if image_result == None or not image_result.get('image'):
        product_image_url = "/static/logo.png"  
    elif image_result:
        product_image_url = f"/static/uploads/{image_result.get('image')}"

    # Get user details if logged in
    user_dict = None
    user_name = "Guest"

    if user_id:
        cursor.execute("SELECT userid, full_name FROM Users WHERE userid = %s", (user_id,))
        user_result = cursor.fetchone()
        if user_result:
            user_dict = {
                'id': user_result.get('userid'),
                'full_name': user_result.get('full_name', user_id)
            }
            user_name = user_dict.get('full_name', user_id)

    # Get ALL related products from same category (no limit)
    related_products = []
    categoryid = product.get('categoryid')
    try:
        if categoryid:
            shop_ids = session.get("shop_ids", [])
            print("Related products query - categoryid:", categoryid, "shop_ids:", shop_ids)
            if shop_ids:
                placeholders = ','.join(['%s'] * len(shop_ids))
                cursor.execute(f"""SELECT p.product_id, p.name, p.price, p.tax, p.stock, p.image,
                    s.name as shop_name 
                    FROM Products p 
                    JOIN Shops s ON p.shop_id = s.shopid
                    WHERE p.categoryid = %s 
                    AND p.product_id != %s 
                    AND s.shopid IN ({placeholders}) 
                    ORDER BY p.product_id""", 
                    (categoryid, product_id, *shop_ids))
            related_results = cursor.fetchall()
            for rel_product in related_results:
                rel_product_dict = dict(rel_product)
                print("Related product:", rel_product_dict)
                rel_product_dict['image_url'] = f"/static/uploads/{rel_product_dict.get('image')}" if rel_product_dict.get('image') else "/static/logo.png"
                related_products.append(rel_product_dict)
    except Exception as e:
        print(f"Error fetching related products: {e}")
        related_products = []

    # Get cart count
    cart_count = 0
    if user_id:
        try:
            cursor.execute("SELECT cartid FROM Carts WHERE userid = %s LIMIT 1", (user_id,))
            cart_result = cursor.fetchone()
            if cart_result:
                cart_id = cart_result.get('cartid')
                cursor.execute("SELECT COUNT(*) as count FROM Cart_Items WHERE cartid = %s", (cart_id,))
                count_result = cursor.fetchone()
                cart_count = count_result.get('count', 0)
        except Exception as e:
            print(f"Error getting cart count: {e}")

    # Get category name
    category_name = ""
    if categoryid:
        cursor.execute("SELECT name FROM Categories WHERE categories_id = %s", (categoryid,))
        cat_result = cursor.fetchone()
        if cat_result:
            category_name = cat_result.get('name', '')

    return render_template('product_description.html',
                         user=user_dict,
                         user_name=user_name,
                         product=product,
                         product_image_url=product_image_url,
                         category_name=category_name,
                         related_products=related_products,
                         cart_count=cart_count)


@app.route('/review/<int:product_id>')
@login_required
def review_product(product_id):

    """Product review page using get_db() connection"""
    try:
        # Get database connection
        conn, cur = get_db()

        # 1. Get product details with category name and description
        cur.execute("""
            SELECT p.product_id, p.name, p.price, p.image, p.shop_id,
                   c.name as category_name,
                   pd.description1, pd.description2, pd.description3,
                   pd.description4, pd.description5
            FROM Products p
            LEFT JOIN Categories c ON p.categoryid = c.categories_id
            LEFT JOIN product_desc pd ON p.product_id = pd.product_id
            WHERE p.product_id = %s
        """, (product_id,))

        product = cur.fetchone()

        if not product:
            return "Product not found", 404

        # Get current user from session
        user_id = session.get('user', 1)
        username = session.get('user', 1)
        # 2. Check if user already reviewed this product
        # Note: Your rating table uses 'userid' column (string), not 'user_id'
        cur.execute("""
            SELECT rating_id, rating_value, rating_title, rating_comment,
                   helpful_count, verified_purchase, created_at
            FROM rating
            WHERE product_id = %s AND userid = %s
        """, (product_id, str(user_id)))  # Convert user_id to string for userid column

        existing_review = cur.fetchone()

        # 3. Get product rating statistics
        cur.execute("""
            SELECT
                COUNT(*) as total_reviews,
                AVG(rating_value) as average_rating,
                SUM(CASE WHEN rating_value = 5 THEN 1 ELSE 0 END) as five_star,
                SUM(CASE WHEN rating_value = 4 THEN 1 ELSE 0 END) as four_star,
                SUM(CASE WHEN rating_value = 3 THEN 1 ELSE 0 END) as three_star,
                SUM(CASE WHEN rating_value = 2 THEN 1 ELSE 0 END) as two_star,
                SUM(CASE WHEN rating_value = 1 THEN 1 ELSE 0 END) as one_star
            FROM rating
            WHERE product_id = %s
        """, (product_id,))

        stats = cur.fetchone()

        # 4. Get recent reviews - Note: no users table join since userid is string
        cur.execute("""
            SELECT
                r.rating_id, r.rating_value, r.rating_title, r.rating_comment,
                r.helpful_count, r.verified_purchase, r.created_at,
                r.userid as username  # Using userid as username since it's stored as string
            FROM rating r
            WHERE r.product_id = %s
            ORDER BY r.created_at DESC
            LIMIT 5
        """, (product_id,))

        reviews = cur.fetchall()

        # 5. Check if user has purchased this product (for verified badge)
        try:
            cur.execute("""
                SELECT COUNT(*) as purchase_count
                FROM Orders o
                JOIN Order_items oi ON o.orderid = oi.order_id
                WHERE o.userid = %s  # Changed to userid to match your schema
                  AND oi.product_id = %s
                  AND o.status = 'delivered'
            """, (str(user_id), product_id))  # Convert user_id to string

            purchase_result = cur.fetchone()
            has_purchased = purchase_result['purchase_count'] > 0 if purchase_result else False
        except Exception as e:
            print(f"Purchase check error (table might not exist): {e}")
            has_purchased = False  # Default to False if orders table doesn't exist

        # Close cursor and connection
        cur.close()
        conn.close()

    except Exception as e:
        print(f"Database error: {e}")
        return f"Database error: {e}", 500

    # Prepare product description from multiple fields
    description_parts = []
    for i in range(1, 6):
        desc_key = f'description{i}'
        if product.get(desc_key):
            description_parts.append(product[desc_key])
    product_description = " | ".join(description_parts) if description_parts else "No description available"

    # Prepare product data
    product_data = {
        'id': product['product_id'],
        'name': product['name'],
        'price': float(product['price']) if product['price'] else 0,
        'category': product['category_name'] or 'Uncategorized',
        'image_url': f"product_{product['product_id']}.png",
        'description': product_description,
        'shop_id': product['shop_id']
    }

    # Prepare statistics
    if stats and stats['total_reviews'] > 0:
        average_rating = float(stats['average_rating']) if stats['average_rating'] else 0
        stats_dict = {
            'average_rating': round(average_rating, 1),
            'total_reviews': stats['total_reviews'],
            'rating_counts': {
                5: stats['five_star'] or 0,
                4: stats['four_star'] or 0,
                3: stats['three_star'] or 0,
                2: stats['two_star'] or 0,
                1: stats['one_star'] or 0
            }
        }
    else:
        stats_dict = {
            'average_rating': 0,
            'total_reviews': 0,
            'rating_counts': {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
        }

    # Calculate rating distribution percentages
    rating_distribution = {}
    if stats_dict['total_reviews'] > 0:
        for i in range(5, 0, -1):
            count = stats_dict['rating_counts'][i]
            percentage = (count / stats_dict['total_reviews']) * 100
            rating_distribution[i] = round(percentage, 1)
    else:
        rating_distribution = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}

    # Format reviews for template
    review_list = []
    for review in reviews:
        review_list.append({
            'rating_id': review['rating_id'],
            'rating_value': review['rating_value'],
            'rating_title': review['rating_title'],
            'rating_comment': review['rating_comment'],
            'helpful_count': review['helpful_count'],
            'verified_purchase': bool(review['verified_purchase']),  # Convert tinyint to boolean
            'created_at': review['created_at'].strftime('%B %d, %Y') if review['created_at'] else '',
            'username': review['username'] or f"User {review['rating_id']}"  # Use userid as username
        })

    # Format existing review if exists
    existing_review_data = None
    if existing_review:
        existing_review_data = {
            'rating_id': existing_review['rating_id'],
            'rating_value': existing_review['rating_value'],
            'rating_title': existing_review['rating_title'],
            'rating_comment': existing_review['rating_comment'],
            'helpful_count': existing_review['helpful_count'],
            'verified_purchase': bool(existing_review['verified_purchase']),
            'created_at': existing_review['created_at'].strftime('%B %d, %Y') if existing_review['created_at'] else ''
        }

    # Prepare context for template
    context = {
        'product': product_data,
        'existing_review': existing_review_data,
        'average_rating': stats_dict['average_rating'],
        'average_rating_rounded': int(round(stats_dict['average_rating'])),
        'total_reviews': stats_dict['total_reviews'],
        'rating_counts': stats_dict['rating_counts'],
        'rating_distribution': rating_distribution,
        'reviews': review_list,
        'has_purchased': has_purchased,
        'current_user': {
            'id': user_id,
            'username': username
        }
    }

    return render_template('write_review.html', **context)


@app.route('/submit-review/<int:product_id>', methods=['POST'])
@login_required
def submit_review_route(product_id):

    """Handle review submission using get_db()"""
    if request.method != 'POST':
        return redirect(f'/review/{product_id}')

    try:
        # Get form data
        rating_value = request.form.get('rating', type=int)
        rating_title = request.form.get('title', '').strip()
        rating_comment = request.form.get('comment', '').strip()

        # Validate rating
        if not rating_value or rating_value < 1 or rating_value > 5:
            flash('Please select a rating between 1-5 stars', 'error')
            return redirect(f'/review/{product_id}')

        user_id = session.get('user', 1)
        conn, cur = get_db()

        # Check if user already reviewed this product
        cur.execute("""
            SELECT rating_id FROM rating
            WHERE product_id = %s AND userid = %s
        """, (product_id, str(user_id)))  # userid is string

        if cur.fetchone():
            flash('You have already reviewed this product!', 'error')
            cur.close()
            conn.close()
            return redirect(f'/review/{product_id}')

        # Check if user has purchased this product (for verified purchase)
        has_purchased = False
        try:
            cur.execute("""
                SELECT COUNT(*) as purchase_count
                FROM orders o
                JOIN order_items oi ON o.orderid = oi.order_id
                WHERE o.userid = %s
                  AND oi.product_id = %s
                  AND o.status = 'delivered'
            """, (str(user_id), product_id))

            purchase_result = cur.fetchone()
            has_purchased = purchase_result['purchase_count'] > 0 if purchase_result else False
        except Exception as e:
            print(f"Purchase check error: {e}")
            has_purchased = False  # Default to False

        # Insert the new review - Note: userid column stores string
        cur.execute("""
            INSERT INTO rating
            (product_id, userid, rating_value, rating_title, rating_comment, verified_purchase)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (product_id, str(user_id), rating_value, rating_title, rating_comment, has_purchased))

        conn.commit()

        # Get the inserted rating ID
        rating_id = cur.lastrowid

        # Close connection
        cur.close()
        conn.close()

        flash('Thank you for your review!', 'success')
        return redirect(f'/review/{product_id}')

    except Exception as e:
        print(f"Error submitting review: {e}")
        flash('An error occurred while submitting your review', 'error')
        return redirect(f'/review/{product_id}')


@app.route('/edit-review/<int:rating_id>', methods=['GET', 'POST'])
@login_required
def edit_review(rating_id):

    """Edit existing review"""
    try:
        conn, cur = get_db()

        if request.method == 'GET':
            # Get review details
            cur.execute("""
                SELECT r.*, p.product_id, p.name as product_name
                FROM rating r
                JOIN Products p ON r.product_id = p.product_id
                WHERE r.rating_id = %s
            """, (rating_id,))

            review = cur.fetchone()

            if not review:
                flash('Review not found', 'error')
                return redirect('/orders')

            # Check if user owns this review
            user_id = session.get('user', 1)
            # Compare userid (string) with user_id (converted to string)
            if review['userid'] != str(user_id):
                flash('You can only edit your own reviews', 'error')
                return redirect("/orders")

            cur.close()
            conn.close()

            return render_template('edit_review.html', review=review)

        elif request.method == 'POST':
            # Update review
            rating_value = request.form.get('rating', type=int)
            rating_title = request.form.get('title', '').strip()
            rating_comment = request.form.get('comment', '').strip()

            # Validate
            if not rating_value or rating_value < 1 or rating_value > 5:
                flash('Please select a rating between 1-5 stars', 'error')
                return redirect(f'/edit-review/{rating_id}')

            user_id = session.get('user', 1)

            # Check ownership - userid is string
            cur.execute("SELECT userid, product_id FROM rating WHERE rating_id = %s", (rating_id,))
            review_check = cur.fetchone()

            if not review_check or review_check['userid'] != str(user_id):
                flash('Unauthorized action', 'error')
                return redirect('/dashboard')

            # Update review
            cur.execute("""
                UPDATE rating
                SET rating_value = %s,
                    rating_title = %s,
                    rating_comment = %s,
                    updated_at = NOW()
                WHERE rating_id = %s
            """, (rating_value, rating_title, rating_comment, rating_id))

            conn.commit()
            cur.close()
            conn.close()

            flash('Review updated successfully!', 'success')
            return redirect(f'/orders')

    except Exception as e:
        print(f"Error editing review: {e}")
        flash('An error occurred', 'error')
        return redirect('/dashboard')


@app.route('/delete-review/<int:rating_id>', methods=['POST'])
@login_required
def delete_review(rating_id):

    """Delete a review"""
    try:
        conn, cur = get_db()

        # Get product_id before deleting
        cur.execute("SELECT product_id FROM rating WHERE rating_id = %s", (rating_id,))
        result = cur.fetchone()

        if not result:
            return jsonify({'success': False, 'message': 'Review not found'}), 404

        product_id = result['product_id']

        # Delete the review
        cur.execute("DELETE FROM rating WHERE rating_id = %s", (rating_id,))
        conn.commit()

        cur.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Review deleted successfully',
            'redirect': f'/review/{product_id}'
        })

    except Exception as e:
        print(f"Error deleting review: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# Helper route to get review statistics for AJAX
@app.route('/api/product/<int:product_id>/stats')
@login_required
def get_product_stats(product_id):
    """Get product rating statistics for AJAX requests"""
    try:
        conn, cur = get_db()

        cur.execute("""
            SELECT
                COUNT(*) as total_reviews,
                AVG(rating_value) as average_rating,
                SUM(CASE WHEN rating_value = 5 THEN 1 ELSE 0 END) as five_star,
                SUM(CASE WHEN rating_value = 4 THEN 1 ELSE 0 END) as four_star,
                SUM(CASE WHEN rating_value = 3 THEN 1 ELSE 0 END) as three_star,
                SUM(CASE WHEN rating_value = 2 THEN 1 ELSE 0 END) as two_star,
                SUM(CASE WHEN rating_value = 1 THEN 1 ELSE 0 END) as one_star
            FROM rating
            WHERE product_id = %s
        """, (product_id,))

        stats = cur.fetchone()

        cur.close()
        conn.close()

        if stats:
            average_rating = float(stats['average_rating']) if stats['average_rating'] else 0
            return jsonify({
                'success': True,
                'total_reviews': stats['total_reviews'],
                'average_rating': round(average_rating, 1),
                'rating_counts': {
                    5: stats['five_star'] or 0,
                    4: stats['four_star'] or 0,
                    3: stats['three_star'] or 0,
                    2: stats['two_star'] or 0,
                    1: stats['one_star'] or 0
                }
            })
        else:
            return jsonify({
                'success': True,
                'total_reviews': 0,
                'average_rating': 0,
                'rating_counts': {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
            })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/billing')
@admin_required
def billing():
    """Render the billing page. If ``invoice_id`` query param is provided the
    template is rendered with the ID so that the frontend can load the
    existing invoice via AJAX."""
    invoice_id = request.args.get('invoice_id', type=int)
    return render_template('billing.html', invoice_id=invoice_id)


@app.route('/billing_view')
@admin_required
def billing_view():
    selected_id = request.args.get('invoice_id', type=int)
    shop_id = session.get('selected_shop_id')

    conn, cur = get_db()
    invoices = []
    invoice_items = []
    selected = None
    try:
        # if an invoice id was requested, load it directly (regardless of session)
        if selected_id:
            cur.execute("""
                SELECT i.*, s.name AS shop_name
                FROM Invoices i
                LEFT JOIN Shops s ON i.shop_id = s.shopid
                WHERE i.invoice_id = %s
            """, (selected_id,))
            selected = cur.fetchone()
            if selected:
                shop_id = selected.get('shop_id')
        # fall back to session shop if nothing found yet
        if shop_id:
            cur.execute("SELECT invoice_id, invoice_number, customer_name, grand_total, shop_id FROM Invoices WHERE shop_id = %s ORDER BY created_at DESC", (shop_id,))
            invoices = cur.fetchall() or []
        # if no selected came from explicit id, pick first of list
        if not selected and invoices:
            selected = invoices[0]
            selected_id = selected.get('invoice_id')
        # finally fetch items for selected invoice if available
        if selected_id:
            cur.execute("""
                SELECT ii.*, p.name AS product_name
                FROM Invoice_Items ii
                LEFT JOIN Products p ON p.product_id = ii.product_id
                WHERE ii.invoice_id = %s
            """, (selected_id,))
            invoice_items = cur.fetchall() or []
    except Exception as e:
        app.logger.error(f"Error loading invoices for billing_view: {e}")
    finally:
        conn.close()

    return render_template(
        'billing_invoices.html',
        invoices=invoices,
        invoice_items=invoice_items,
        selected_invoice=selected
    )


@app.route('/my_invoices')
@login_required
def my_invoices():
    selected_id = request.args.get('invoice_id', type=int)
    customer_email = session.get('email')

    conn, cur = get_db()
    invoices = []
    invoice_items = []
    selected = None

    try:
        if not customer_email:
            flash('Customer email not found in session. Please log in again.', 'error')
            return redirect(url_for('login'))

        # Optionally select a specific invoice (if it belongs to this customer)
        if selected_id:
            cur.execute("""
                SELECT i.*, s.name AS shop_name
                FROM Invoices i
                LEFT JOIN Shops s ON i.shop_id = s.shopid
                WHERE i.invoice_id = %s AND i.customer_email = %s
            """, (selected_id, customer_email))
            selected = cur.fetchone()

        # Load all invoices for this customer
        cur.execute("""
            SELECT i.*, s.name AS shop_name
            FROM Invoices i
            LEFT JOIN Shops s ON i.shop_id = s.shopid
            WHERE i.customer_email = %s
            ORDER BY i.created_at DESC
        """, (customer_email,))
        invoices = cur.fetchall() or []

        # Default to first invoice if none explicitly selected
        if not selected and invoices:
            selected = invoices[0]
            selected_id = selected.get('invoice_id')

        # Load items for selected invoice
        if selected_id:
            cur.execute("""
                SELECT ii.*, p.name AS product_name
                FROM Invoice_Items ii
                LEFT JOIN Products p ON ii.product_id = p.product_id
                WHERE ii.invoice_id = %s
            """, (selected_id,))
            invoice_items = cur.fetchall() or []

    except Exception as e:
        app.logger.error(f"Error loading customer invoices: {e}")
        flash('Unable to load your invoices at this time.', 'error')
    finally:
        conn.close()

    return render_template(
        'billing_invoices.html',
        invoices=invoices,
        invoice_items=invoice_items,
        selected_invoice=selected,
        read_only=True
    )


@app.route('/invoices')
@admin_required
def invoices():
    """Show a simple listing of invoices with links to edit/view them."""
    return render_template('invoices.html')

# API endpoint to create/update invoice
@app.route('/api/invoices', methods=['POST'])
@login_required
def create_invoice():
    """Create a new invoice"""
    conn, cur = get_db()
    if not conn or not cur:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    try:
        data = request.json
        
        # start transaction so stock update + insert is atomic
        conn.start_transaction()
        
        # determine invoice number (client may send one)
        invoice_number = data.get('invoice_number')
        if not invoice_number:
            invoice_number = f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        cur.execute("""
            INSERT INTO Invoices (
                invoice_number,
                customer_name, customer_email, customer_phone,
                customer_address, due_date, shop_id, subtotal, total_tax,
                grand_total, status, created_by, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            invoice_number,
            data['customer']['name'],
            data['customer']['email'],
            data['customer'].get('phone', ''),
            data['customer'].get('address', ''),
            data['due_date'],
            data.get('shop_id', 1),  # Default shop_id
            data['subtotal'],
            data['total_tax'],
            data['grand_total'],
            data.get('status', 'draft'),
            session.get('user_id', 1),  # Get from session
            datetime.now()
        ))
        
        invoice_id = cur.lastrowid
        
        # insert invoice items
        for item in data['items']:
            cur.execute("""
                INSERT INTO Invoice_Items (
                    invoice_id, product_id, description, quantity,
                    unit_price, tax_rate, tax_amount, total
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                invoice_id,
                item.get('product_id'),
                item['description'],
                item['quantity'],
                item['unit_price'],
                item['tax_rate'],
                item['tax_amount'],
                item['total']
            ))
            
            # update product stock if applicable
            if item.get('product_id'):
                cur.execute("""
                    UPDATE Products 
                    SET stock = stock - %s 
                    WHERE product_id = %s AND stock >= %s
                """, (item['quantity'], item['product_id'], item['quantity']))
                
                if cur.rowcount == 0:
                    raise Exception(f"Insufficient stock for product ID {item['product_id']}")
        
        conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Invoice created successfully',
            'invoice_id': invoice_id,
            'invoice_number': invoice_number
        }), 201
        
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:    
        if conn:
            conn.close()

@app.route('/api/invoices/<int:invoice_id>', methods=['PUT'])
@login_required
def update_invoice(invoice_id):
    """Update an existing invoice"""
    conn, cur = get_db()
    if not conn or not cur:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    try:
        data = request.json
        conn.start_transaction()
        
        # read existing status to enforce valid transitions
        cur.execute("SELECT status FROM Invoices WHERE invoice_id = %s", (invoice_id,))
        oldrow = cur.fetchone()
        old_status = oldrow['status'] if oldrow else None
        new_status = data.get('status', 'draft')
        if old_status == 'paid' and new_status not in ('paid', 'cancelled'):
            # invalid transition; ignore request or force paid
            app.logger.warning(f"Attempt to change status from paid to {new_status} on invoice {invoice_id}")
            new_status = 'paid'

        # Update invoice header (including invoice_number)
        cur.execute("""
            UPDATE Invoices SET
                invoice_number = %s,
                customer_name = %s,
                customer_email = %s,
                customer_phone = %s,
                customer_address = %s,
                due_date = %s,
                subtotal = %s,
                total_tax = %s,
                grand_total = %s,
                status = %s,
                updated_at = %s
            WHERE invoice_id = %s
        """, (
            data.get('invoice_number'),
            data['customer']['name'],
            data['customer']['email'],
            data['customer'].get('phone', ''),
            data['customer'].get('address', ''),
            data['due_date'],
            data['subtotal'],
            data['total_tax'],
            data['grand_total'],
            new_status,
            datetime.now(),
            invoice_id
        ))
        
        # Delete existing items
        cur.execute("DELETE FROM Invoice_Items WHERE invoice_id = %s", (invoice_id,))
        
        # Insert updated items
        for item in data['items']:
            cur.execute("""
                INSERT INTO Invoice_Items (
                    invoice_id, product_id, description, quantity,
                    unit_price, tax_rate, tax_amount, total
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                invoice_id,
                item.get('product_id'),
                item['description'],
                item['quantity'],
                item['unit_price'],
                item['tax_rate'],
                item['tax_amount'],
                item['total']
            ))
        
        conn.commit()
        
        # fetch updated invoice_number in case it changed
        cur.execute("SELECT invoice_number FROM Invoices WHERE invoice_id = %s", (invoice_id,))
        numrow = cur.fetchone()
        invoice_number = numrow['invoice_number'] if numrow else None
        return jsonify({
            'success': True,
            'message': 'Invoice updated successfully',
            'invoice_id': invoice_id,
            'invoice_number': invoice_number
        }), 200
        
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/invoices', methods=['GET'])
@login_required
def list_invoices():
    """Return a list of invoices for the current shop.
    Supports optional ``shop_id`` query parameter; otherwise defaults to
    the session-selected shop or 1.
    """
    conn, cur = get_db()
    if not conn or not cur:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    try:
        shop_id = request.args.get('shop_id', type=int) or session.get('selected_shop_id', 1)
        cur.execute(
            """
            SELECT invoice_id, invoice_number, customer_name, customer_email,
                   due_date, grand_total, status, created_at
            FROM Invoices WHERE shop_id = %s
            ORDER BY created_at DESC
            """,
            (shop_id,)
        )
        invoices = cur.fetchall() or []
        conn.close()
        return jsonify({'success': True, 'invoices': invoices}), 200
    except Exception as e:
        if conn:
            conn.close()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/invoices/<int:invoice_id>', methods=['GET'])
@admin_required
def get_invoice(invoice_id):
    """Get a specific invoice by ID"""
    conn, cur = get_db()
    if not conn or not cur:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    try:
        # Get invoice header along with shop name
        cur.execute("""
            SELECT i.*, s.name AS shop_name
            FROM Invoices i
            LEFT JOIN Shops s ON i.shop_id = s.shopid
            WHERE i.invoice_id = %s
        """, (invoice_id,))
        invoice = cur.fetchone()
        
        if not invoice:
            return jsonify({'success': False, 'message': 'Invoice not found'}), 404
        
        # Get invoice items including product names
        cur.execute("""
            SELECT ii.*, p.name AS product_name
            FROM Invoice_Items ii
            LEFT JOIN Products p ON ii.product_id = p.product_id
            WHERE ii.invoice_id = %s
        """, (invoice_id,))
        items = cur.fetchall()
        
        # Format response
        result = {
            'invoice_id': invoice['invoice_id'],
            'invoice_number': invoice['invoice_number'],
            'customer': {
                'name': invoice['customer_name'],
                'email': invoice['customer_email'],
                'phone': invoice['customer_phone'],
                'address': invoice['customer_address']
            },
            'due_date': str(invoice['due_date']),
            'shop_id': invoice['shop_id'],
            'shop_name': invoice.get('shop_name'),
            'subtotal': float(invoice['subtotal']),
            'total_tax': float(invoice['total_tax']),
            'grand_total': float(invoice['grand_total']),
            'status': invoice['status'],
            'items': []
        }
        
        for item in items:
            result['items'].append({
                'item_id': item.get('item_id'),
                'product_id': item.get('product_id'),
                'product_name': item.get('product_name'),
                'description': item['description'],
                'quantity': float(item['quantity']),
                'unit_price': float(item['unit_price']),
                'tax_rate': float(item['tax_rate']),
                'tax_amount': float(item['tax_amount']),
                'total': float(item['total'])
            })
        
        return jsonify({'success': True, 'invoice': result}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

# Fix 1: Add mysql.connector import if not already there
import mysql.connector
from mysql.connector import Error

@app.route("/customer", methods=["GET", "POST"])
@admin_required
def customer():
    shop_name = session.get('selected_shop_name', None)
    if not shop_name:
        shop_name = "Myshop"
    return render_template("create_customer.html", shop_name=shop_name)


@app.route('/api/customers', methods=['GET'])
@admin_required
def get_customers():
    conn, cur = get_db()
    if not conn or not cur:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        shop_id = session.get("selected_shop_id")
        cur.execute('''SELECT c.* 
            FROM customer c
            INNER JOIN user_customer uc ON c.customer_id = uc.customer_id AND c.email = uc.email
            WHERE uc.shopid = %s
            ORDER BY c.customer_id DESC''',(shop_id,))
        
        column_names = [desc[0] for desc in cur.description]
        rows = cur.fetchall()
        result = []
        for row in rows:
            if isinstance(row, dict):
                result.append(row)
            else:
                customer_dict = {}
                for i, col in enumerate(column_names):
                    if i < len(row):
                        customer_dict[col] = row[i]
                    else:
                        customer_dict[col] = None
                result.append(customer_dict)
        return jsonify(result)
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/api/customers/search', methods=['GET'])
def search_customers():
    search_term = request.args.get('q', '')
    
    if not search_term:
        return get_customers()
    
    conn, cur = get_db()
    shopid = session.get("selected_shop_id")
    if not conn or not cur:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        query = """
            SELECT c.*
            FROM customer c
            JOIN user_customer uc ON c.customer_id = uc.customer_id
            WHERE uc.shopid = %s AND (
                c.customer_name LIKE %s
                OR c.customer_mobile_number LIKE %s
                OR c.email LIKE %s
                OR c.city LIKE %s
                OR c.Vilage LIKE %s
                OR c.pincode LIKE %s
            )
            ORDER BY c.customer_id DESC
        """
        search_pattern = f"%{search_term}%"
        cur.execute(query, (shopid,search_pattern, search_pattern, search_pattern, 
                           search_pattern, search_pattern, search_pattern))
        
        customers = cur.fetchall()  
        return jsonify(customers)
        
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()


# Fix 4: Create customer with proper error handling
@app.route('/api/customers', methods=['POST'])
@admin_required
def create_customer():
    app.logger.debug("REQ POST /api/customers")
    data = request.json
    app.logger.debug(f"Request data: {data}")
    
    # Validate required fields
    required_fields = ['customer_name', 'customer_mobile_number', 'address1', 
                      'city', 'pincode', 'Vilage', 'email']
    
    for field in required_fields:
        if field not in data or not data[field]:
            app.logger.error(f"Missing required field: {field}")
            return jsonify({'error': f'Missing required field: {field}'}), 400

    conn, cur = get_db()
    if not conn or not cur:
        app.logger.error("Database connection failed")
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        # Get shop_id from session or request
        shop_id = session.get('selected_shop_id', data.get('shopid'))
        app.logger.debug(f"Using shop_id: {shop_id}")
        
        if not shop_id:
            app.logger.error("No shop selected")
            return jsonify({'error': 'No shop selected'}), 400
        
        # Step 1: Check if customer already exists by email
        customer_created = False
        cur.execute("SELECT customer_id FROM customer WHERE email = %s", (data['email'],))
        existing_customer = cur.fetchone()
        
        if existing_customer:
            # Customer exists - use existing ID
            customer_id = existing_customer['customer_id']  # Dictionary access since cursor(dictionary=True)
            app.logger.debug(f"Customer already exists with ID: {customer_id}")
            cur.execute("SELECT * FROM user_customer WHERE email = %s AND customer_id = %s AND shopid = %s",
                (data['email'], customer_id, shop_id))
            existing_relation = cur.fetchone()
            if not existing_relation:
                cur.execute("insert into user_customer (email, customer_id, shopid) values (%s, %s, %s)", (data['email'], customer_id, shop_id))
                conn.commit()
                app.logger.debug(f"Linked customer {customer_id} to user {data['email']} for shop {shop_id}")
                customer_created = True
            else:
                app.logger.debug(f"Relationship already exists for customer {customer_id}, user {data['email']}, shop {shop_id}")
                customer_created = False
        else:
            # Customer does NOT exist - insert new customer
            query = """
                INSERT INTO customer 
                (customer_name, customer_mobile_number, address1, address2, 
                 city, pincode, Vilage, email)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                data['customer_name'],
                data['customer_mobile_number'],
                data['address1'],
                data.get('address2', ''),
                data['city'],
                data['pincode'],
                data['Vilage'],
                data['email']
            )
            
            app.logger.debug(f"Executing insert query with values: {values}")
            cur.execute(query, values)
            conn.commit()
            customer_id = cur.lastrowid
            app.logger.debug(f"New customer created with ID: {customer_id}")
            cur.execute("SELECT * FROM user_customer WHERE email = %s AND customer_id = %s AND shopid = %s",
                (data['email'], customer_id, shop_id))
            existing_relation = cur.fetchone()
            if not existing_relation:
                cur.execute("insert into user_customer (email, customer_id, shopid) values (%s, %s, %s)", (data['email'], customer_id, shop_id))
                conn.commit()
                app.logger.debug(f"Linked customer {customer_id} to user {data['email']} for shop {shop_id}")
                customer_created = True
            else:
                app.logger.debug(f"Relationship already exists for customer {customer_id}, user {data['email']}, shop {shop_id}")
                customer_created = False
       
        # Return appropriate response
        if customer_created:
            return jsonify({
                'message': 'Customer created successfully',
                'customer_id': customer_id
            }), 201
        else:
            return jsonify({
                'message': 'Customer already exists',
                'customer_id': customer_id
            }), 200
        
    except mysql.connector.Error as e:
        app.logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route("/khatabook", methods=["GET", "POST"])
@admin_required
def khatabook():
    conn, cur = get_db()
    try:
        # Get shop_id from session or form
        shop_id = session.get('selected_shop_id')
        if not shop_id:
            flash("Please select a shop first.", "error")
            return redirect(url_for('admin_dashboard'))

        if request.method == "POST":
            action = request.form.get('action')
            if action == 'add_party':
                name = request.form.get('name')
                phone = request.form.get('phone')
                address = request.form.get('address')
                party_type = request.form.get('type')
                if not name or not party_type:
                    flash("Name and type are required.", "error")
                else:
                    cur.execute("INSERT INTO parties (name, phone, address, type, shop_id) VALUES (%s, %s, %s, %s, %s)",
                               (name, phone, address, party_type, shop_id))
                    conn.commit()
                    flash("Party added successfully.", "success")
            elif action == 'add_transaction':
                party_id = request.form.get('party_id')
                trans_type = request.form.get('type')
                amount = request.form.get('amount')
                description = request.form.get('description')
                trans_date = request.form.get('date')
                if not party_id or not trans_type or not amount or not trans_date:
                    flash("All fields are required.", "error")
                else:
                    cur.execute("INSERT INTO transactions (party_id, type, amount, description, transaction_date, created_by, shop_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                               (party_id, trans_type, amount, description, trans_date, session['user'], shop_id))
                    conn.commit()
                    flash("Transaction added successfully.", "success")

        # Get parties
        cur.execute("SELECT * FROM parties WHERE shop_id = %s ORDER BY name", (shop_id,))
        parties = cur.fetchall()

        # Get transactions for each party (last 10)
        for party in parties:
            cur.execute("SELECT * FROM transactions WHERE party_id = %s ORDER BY transaction_date DESC, created_at DESC LIMIT 10", (party['id'],))
            party['transactions'] = cur.fetchall()

        conn.close()
        return render_template('khatabook.html', parties=parties)
    except Exception as e:
        conn.close()
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route("/api/khatabook/parties", methods=["GET"])
@admin_required
def api_khatabook_parties():
    conn, cur = get_db()
    try:
        shop_id = session.get('selected_shop_id')
        if not shop_id:
            return jsonify({"success": False, "message": "No shop selected"}), 400

        cur.execute("SELECT id, name, balance FROM parties WHERE shop_id = %s ORDER BY name", (shop_id,))
        parties = cur.fetchall()
        conn.close()
        return jsonify({"success": True, "parties": parties})
    except Exception as e:
        conn.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/khatabook/transactions/<int:party_id>", methods=["GET"])
@admin_required
def api_khatabook_transactions(party_id):
    conn, cur = get_db()
    try:
        shop_id = session.get('selected_shop_id')
        if not shop_id:
            return jsonify({"success": False, "message": "No shop selected"}), 400

        # Get party name
        cur.execute("SELECT name FROM parties WHERE id = %s AND shop_id = %s", (party_id, shop_id))
        party = cur.fetchone()
        party_name = party['name'] if party else 'Unknown Party'

        cur.execute("SELECT * FROM transactions WHERE party_id = %s AND shop_id = %s ORDER BY transaction_date DESC, created_at DESC", (party_id, shop_id))
        transactions = cur.fetchall()
        conn.close()
        return jsonify({"success": True, "transactions": transactions, "party_name": party_name})
    except Exception as e:
        conn.close()
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)