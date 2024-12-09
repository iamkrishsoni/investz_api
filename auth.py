from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import re
import os
import jwt
import base64
import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from bson.json_util import dumps

app = Flask(__name__)
CORS(app)  
app.config['SECRET_KEY'] = 'INVESTZ123'  
port = 7000
# MongoDB connection URI
mongo_uri = "mongodb+srv://TEST:12345@mubustest.yfyj3.mongodb.net/investz?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)
db = client["investz"]
user_collection = db["USER"]
portfolio_collection = db["PORTFOLIO"]

@app.route('/')
def home():
    users = user_collection.find()  # Retrieve all documents
    users_list = list(users)  # Convert cursor to list
    return dumps(users_list), 200


# Route to enter data into the USER collection
@app.route('/signup', methods=['POST'])
def add_user():
    data = request.get_json()
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    contact = data.get("contact")
    email = data.get("email").lower()
    password = data.get("password")
    risk_level = data.get("risk_level")
    profile_photo = request.files.get("profile_photo")
    photo_data = profile_photo.read() if profile_photo else None
    
    if not password:
        return jsonify({"message": "Password is required"}), 201
    
    if not first_name:
        return jsonify({"message": "First Name is required"}), 201
    
    if not last_name:
        return jsonify({"message": "Last Name is required"}), 201
    
    if not contact:
        return jsonify({"message": "Contact is required"}), 201
    
    if not email:
        return jsonify({"message": "Email is required"}), 201
    
    if len(contact)!=10:
        return jsonify({"message": "Contact Format is wrong"}), 201
    
    if len(password)<6:
        return jsonify({"message": "Password length should be atleast 6"}), 201
    
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({"message": "Email format is not correct"}), 201    
    
    email_id = user_collection.find_one({"email": email})
    if email_id:
        return jsonify({"message": "Email id already registered"}), 201
    
    contact_number = user_collection.find_one({"contact": contact})
    if contact_number:
        return jsonify({"message": "Contact number already registered"}), 201
    
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    user_data = {
        "first_name": first_name,
        "last_name": last_name,
        "contact": contact,
        "email": email,
        "password": hashed_password,
        "profile_photo": photo_data,
        "risk_level": risk_level
    }

    user_collection.insert_one(user_data)
    return jsonify({"message": "User added successfully"}), 201

# Route for user login and JWT generation
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email').lower()
    password = data.get('password')
    
    if not email:
        return jsonify({"message": "Email is required"}), 201
    
    if not password:
        return jsonify({"message": "Password is required"}), 201
    
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({"message": "Email format is not correct"}), 201 
    
    # Find user by email
    user = user_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "Email is not registered"}), 201
    
    # Check if password matches
    if not check_password_hash(user['password'], password):
        return jsonify({"message": "Invalid Password"}), 201
    
    # Generate JWT token
    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    # Convert profile photo to Base64 if it exists
    profile_photo_base64 = None
    if user.get('profile_photo'):
        profile_photo_base64 = base64.b64encode(user['profile_photo']).decode('utf-8')
    
    # Return user details along with the token
    user_data = {
        "first_name": user['first_name'],
        "last_name": user['last_name'],
        "contact": user['contact'],
        "email": user['email'],
        "risk_level":user['risk_level'],
        "profile_photo": profile_photo_base64,
        "token": token
    }
    return jsonify(user_data), 200

@app.route('/save_portfolio', methods=['POST'])
def save_portfolio():
    data = request.get_json()
    email = data.get('email')
    stock = data.get('stock')
    purchase = data.get('purchase')
    current = data.get('current')
    quantity = data.get('quantity')
    pl = data.get('pl')
    
    if not all([email, stock, purchase, current, quantity, pl]):
        return jsonify({"error": "All fields (email, stock, purchase, current, quantity, pl) are required"}), 400
    timestamp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    stock_details = {
        "stock": stock,
        "purchase": purchase,
        "current": current,
        "quantity": quantity,
        "pl": pl,
        "timestamp": timestamp
    }
    
    existing_portfolio = portfolio_collection.find_one({"email": email})

    if existing_portfolio:
        # Append to existing portfolio
        portfolio_collection.update_one(
            {"email": email},
            {"$push": {"portfolio": stock_details}}
        )
        message = "Portfolio updated successfully"
    else:
        # Create new entry
        new_entry = {
            "email": email,
            "portfolio": [stock_details]
        }
        portfolio_collection.insert_one(new_entry)
        message = "New portfolio created successfully"

    return jsonify(stock_details), 200

@app.route('/update-profile-photo', methods=['POST'])
def update_profile_photo():
    data = request.form
    email = data.get("email")
    risk_level = data.get("risk_level")
    profile_photo = request.files.get("profile_photo")  # Get the profile photo from the request

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Find the user by email
    user = user_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    update_data = {}

    # Check if profile_photo is provided
    if profile_photo:
        photo_data = profile_photo.read()
        print("photo_data:", photo_data)
        update_data["profile_photo"] = photo_data

    # Check if risk_level is provided
    if risk_level is not None:  # Only update risk_level if provided
        update_data["risk_level"] = risk_level

    if not update_data:  # No data to update
        return jsonify({"error": "No data to update"}), 400

    # Update the user's profile photo and/or risk_level
    user_collection.update_one(
        {"email": email},
        {"$set": update_data}
    )

    return jsonify({"message": "Profile updated successfully"}), 200


# Decorator to verify the JWT token
def token_required(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 403
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return wrapper

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)
