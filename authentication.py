from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
import firebase_admin.auth as firebase_auth
app = Flask(__name__)
CORS(app) 
# Initialize Firebase Admin SDK
cred = credentials.Certificate('investz-4bc99-firebase-adminsdk-opsnr-83bde6842b.json')
firebase_admin.initialize_app(cred)
db = firestore.client()


@app.route('/add_user', methods=['POST'])
def add_user():
    # Get data from the request
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    gender = data.get('gender')
    contact = data.get('contact')
    about = data.get('about')

    # Create a new user document in the "USER" collection
    user_ref = db.collection('USER').document(email)  # Use email as document ID
    user_ref.set({
        'name': name,
        'email': email,
        'gender': gender,
        'contact': contact,
        'about': about
    })

    return jsonify({"message": "User added successfully!"}), 201



@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    first_name= data.get('first_name')
    last_name= data.get('last_name')
    contact=data.get('contact')
    email = data.get('email')
    password = data.get('password')

    try:
       
        user = auth.create_user(
        
            email=email,
            password=password
        )
        

        return jsonify({"message": "User created successfully", "user_id": user.uid}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    try:
        # Verify user by checking credentials
        user = auth.get_user_by_email(email)
        
        # Firebase does not directly handle password verification, you can use Firebase client SDK in your front-end to authenticate
        # In this case, assume client validates the password using Firebase JS SDK or another method
        
        return jsonify({"message": "Login successful", "user_id": user.uid}), 200
    except auth.UserNotFoundError:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400



@app.route('/delete_user', methods=['POST'])
def delete_user():
    try:
        # Get email and password from the request body
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        id_token = data.get('id_token')  # Get the ID token sent from client

        if not id_token:
            return jsonify({"error": "ID token is required"}), 400

        # Verify the ID token and decode the user info
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token.get('uid')

        # If UID is found, delete the user from Firebase Authentication
        if uid:
            auth.delete_user(uid)
            return jsonify({"message": "User deleted successfully"}), 200
        else:
            return jsonify({"error": "User authentication failed"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)


