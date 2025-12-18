import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

# Load dataset
df = pd.read_csv("ml_models/spam.csv")

# Normalize column names (handle common formats)
if "label" not in df.columns:
    df.columns = ["label", "text"]

df["label"] = df["label"].map({"ham": 0, "spam": 1})

X = df["text"]
y = df["label"]

# Vectorization
vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
X_vec = vectorizer.fit_transform(X)

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42
)

# Train model
model = LogisticRegression(max_iter=2000)
model.fit(X_train, y_train)

# Evaluation
pred = model.predict(X_test)
print("TEXT MODEL RESULTS")
print(classification_report(y_test, pred))

# Save model
joblib.dump(model, "ml_models/text_phishing_model.pkl")
joblib.dump(vectorizer, "ml_models/text_vectorizer.pkl")

print("✅ Text phishing model trained & saved")
