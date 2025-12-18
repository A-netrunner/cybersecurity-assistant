import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

# Load parquet datasets
train_df = pd.read_parquet("ml_models/Training.parquet")
test_df = pd.read_parquet("ml_models/Testing.parquet")

# Expected columns: "text" or "url", "label"
X_train = train_df["text"]
y_train = train_df["label"]

X_test = test_df["text"]
y_test = test_df["label"]

# Vectorization
vectorizer = TfidfVectorizer(stop_words="english", max_features=6000)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Train model
model = LogisticRegression(max_iter=3000)
model.fit(X_train_vec, y_train)

# Evaluation
pred = model.predict(X_test_vec)
print("PARQUET MODEL RESULTS")
print(classification_report(y_test, pred))

# Save model
joblib.dump(model, "ml_models/parquet_model.pkl")
joblib.dump(vectorizer, "ml_models/parquet_vectorizer.pkl")

print("✅ Parquet-based model trained & saved")
