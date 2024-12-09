from flask import Flask, jsonify
import requests
from flask_cors import CORS
from textblob import TextBlob
import re


app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

api_url = 'https://www.alphavantage.co/query?function=NEWS_SENTIMENT&tickers=IBM&apikey=ZVCGG3ZMTYIIP87Z'
port = 9000

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
    return jsonify({'status': 'NEWS SENTIMENT BACKEND IS RUNNING'})

# Latest news route
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

# Start the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)
