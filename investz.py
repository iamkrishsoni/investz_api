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
import requests
from textblob import TextBlob
from bson import ObjectId

app = Flask(__name__)
CORS(app)  
app.config['SECRET_KEY'] = 'INVESTZ123'  
port=443

api_url = 'https://www.alphavantage.co/query?function=NEWS_SENTIMENT&tickers=IBM&apikey=ZVCGG3ZMTYIIP87Z'
# MongoDB connection URI
mongo_uri = "mongodb+srv://TEST:12345@mubustest.yfyj3.mongodb.net/investz?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)
db = client["investz"]
user_collection = db["USER"]
portfolio_collection = db["PORTFOLIO"]



def analyze_sentiment(text):
    """
    Analyze the sentiment of a given text using TextBlob.
    Returns polarity (-1 to 1) and subjectivity (0 to 1) scores,
    along with a sentiment label.
    
    Parameters:
    text (str): The text to analyze
    
    Returns:
    dict: Dictionary containing sentiment analysis results
    """
    # Clean the text
    def clean_text(text):
        # Remove special characters and digits
        text = re.sub(r'[^a-zA-Z\s]', '', text)
        # Convert to lowercase
        text = text.lower()
        # Remove extra whitespace
        text = ' '.join(text.split())
        return text
    
    # Clean the input text
    cleaned_text = clean_text(text)
    
    # Create TextBlob object
    blob = TextBlob(cleaned_text)
    
    # Get sentiment scores
    polarity = blob.sentiment.polarity
    subjectivity = blob.sentiment.subjectivity
    
    # Define keywords that could indicate a neutral sentiment
    neutral_keywords = ["mixed", "uncertainty", "subdued", "no clear direction", "balancing"]
    
    # Check for presence of neutral keywords
    if any(word in cleaned_text for word in neutral_keywords):
        sentiment = 'Neutral'
    else:
        # Determine sentiment label based on polarity
        if polarity > 0:
            sentiment = 'Positive'
        elif polarity < 0:
            sentiment = 'Negative'
        else:
            sentiment = 'Neutral'
    
    # Calculate intensity
    intensity = abs(polarity)
    if intensity < 0.3:
        strength = 'Weak'
    elif intensity < 0.6:
        strength = 'Moderate'
    else:
        strength = 'Strong'
    
    return {
        'polarity': polarity,
        'subjectivity': subjectivity,
        'sentiment': sentiment,
        'strength': strength,
        'cleaned_text': cleaned_text
    }






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

@app.route('/get_portfolio', methods=['POST'])
def get_portfolio():
    try:
        # Get the email from the POST request body
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({
                "status": "error",
                "message": "Email is required"
            }), 400

        # Find the portfolio for the given email
        portfolio = portfolio_collection.find_one({"email": email})

        if not portfolio:
            check=[]
            return jsonify(check), 200

        # Convert ObjectId to string for JSON compatibility
        portfolio['_id'] = str(portfolio['_id'])

        return jsonify(portfolio['portfolio']), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/latest-news')
def latest_news():
    try:
        # Make the API call using requests
        response = requests.get(api_url)
        data = response.json()
        result=[]
        for i in data['feed']:
            results = analyze_sentiment(i['summary'])
            result.append({"title": i['title'],"summary":i['summary'] , "url":i['url'] , "sentiment":results['sentiment'] ,
                           "strength": results['strength'] , "polarity_score": results['polarity'] , "subjectivity_score":results['subjectivity']} )
        return jsonify(result)
        

    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


@app.route('/get-stock-data', methods=['POST'])
def get_stock_data():
    data = request.get_json()
    symbol = data.get('symbol')
    
    if not symbol:
        return jsonify({"error": "No symbol provided"}), 400
    
    symbol_name = symbol.split('.')[0]

    url = "https://www.alphavantage.co/query"
    params = {
        'function': 'TIME_SERIES_DAILY',
        'symbol': f"{symbol_name}.BSE", 
        'outputsize': 'full',
        'apikey': "GKW8AS974VHJOE06"
    }

    response = requests.get(url, params=params)
    result = response.json()
    
    if response.status_code == 200:
        time_series = result.get('Time Series (Daily)', {})
     
        sorted_dates = sorted(
            time_series.keys(), 
            key=lambda x: datetime.datetime.strptime(x, '%Y-%m-%d'),  # Updated usage
            reverse=True
        )
        latest_date = sorted_dates[0]
        latest_data = time_series[latest_date]

        return jsonify(latest_data['4. close'])
    
    else:
        return jsonify({"error": "Failed to fetch data from Alpha Vantage"}), 500

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