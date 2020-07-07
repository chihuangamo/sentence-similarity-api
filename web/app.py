from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient('mongodb://mongodb:27017/')
db = client.smDB
col = db.users

salt = bcrypt.gensalt(7)

def validate_registration(user_data):
    if not 'username' in user_data or not 'password' in user_data:
        return ({
            'status': 301,
            'message': 'Missing username or password'
        })

    if not user_data['username'] or not user_data['password']:
        return ({
            'status': 301,
            'message': 'Invalid username or password'
        })
    
    if col.find_one({'username': user_data['username']}):
        return ({
            'status': 300,
            'messate': 'Username already exists'
        })
    return ({'status': 200})

class Register(Resource):
    def post(self):
        data = request.get_json()
        validation = validate_registration(data)
        if validation['status'] != 200:
            return jsonify(validation)
        
        username = data['username']
        password = data['password']
        password_hashed = bcrypt.hashpw(password.encode(), salt)
        col.insert_one({
            'username': username,
            'password_hashed': password_hashed,
            'tokens': 20
        })
        return jsonify(validation)

def validate_user(data):
    if not 'username' in data or not 'password' in data:
        return ({
            'status': 301,
            'message': 'Invalid username or password'
        })

    if not data['username'] or not data['password']:
        return ({
            'status': 301,
            'message': 'Invalid username or password'
        })

    username = data['username']
    password = data['password']
    password_hashed = bcrypt.hashpw(password.encode(), salt)
    if not col.find_one({'username': username}):
        return ({
            'status': 305,
            'message': 'User not exists'
        })

    if col.find_one({'username': username})['password_hashed'] != password_hashed:
        return ({
            'status': 302,
            'message': "Wrong password"
        })
    
    return ({'status': 200})

def validate_text(data):
    if not 'text1' in data or not 'text2' in data:
        return ({
            'status': 302,
            'message': "Invalid text input"
        })
    return ({'status': 200})

def validate_tokens(username):
    if col.find_one({'username': username})['tokens'] == 0:
        return ({
            'status': 303,
            'message': "Out of tokens"
        })
    return ({'status': 200})

def minus_tokens(username):
        col.update_one({'username': username}, {'$inc': {'tokens': -1}})

def get_similiarity(text1, text2):
    sm = spacy.load('en_core_web_sm')
    text1_sm = sm(text1)
    text2_sm = sm(text2)

    return text1_sm.similarity(text2_sm)

class TextSimilarity(Resource):
    def post(self):
        data = request.get_json()
        user_validation = validate_user(data)
        if user_validation['status'] != 200:
            return jsonify(user_validation) 
        text_validation = validate_text(data)
        if text_validation['status'] != 200:
            return jsonify(text_validation) 

        username = data['username']
        tokens_validation =  validate_tokens(username)
        if  tokens_validation['status'] != 200:
            return jsonify(tokens_validation) 
        
        text1 = data['text1']
        text2 = data['text2']
        similarity = get_similiarity(text1, text2)

        minus_tokens(username)
        return jsonify({
            'status': 200,
            'similarity': similarity
        })

ADMIN_PASSWORD = '7693'
class Refill(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        admin_pw = data['admin_pw']
        if not col.find_one({'username': username}):
            return ({
                'status': 304,
                'message': 'User not exists'
            })

        if admin_pw != ADMIN_PASSWORD:
            return jsonify({
                'status': 305,
                'message': 'Invalid admin password'
            })

        col.update_one({"username": username}, {'$set':{'tokens': 20}})
        return jsonify({'status': 200})


api.add_resource(Register, '/register')
api.add_resource(TextSimilarity, '/similarity')
api.add_resource(Refill, '/refill')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)