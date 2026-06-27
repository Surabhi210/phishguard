import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

data = {
    "text": [
        # ── PHISHING (label=1) ──
        "urgent verify your paypal account click login password limited confirm security otp unusual activity",
        "your paypal account has been limited verify immediately click here restore access password otp suspend",
        "congratulations you won lottery claim free gift prize reward click now winner selected",
        "action required your bank account suspended verify credentials wire transfer immediately deactivated",
        "unusual activity detected login immediately confirm your identity password reset account security",
        "your apple id has been locked verify account security click link immediately credentials",
        "amazon account alert confirm payment method update billing credentials now suspended",
        "microsoft security alert your account compromised verify identity immediately click login",
        "dear customer account deactivated validate credentials urgent action required password",
        "bitcoin reward claim free offer winner selected click link enter details prize gift",
        "invoice payment overdue click to confirm wire transfer credentials required urgent",
        "your netflix account will expire update payment method immediately click here login",
        "google security alert unusual signin detected verify account now click link password",
        "citibank wire transfer pending confirm credentials cancel immediately login bank",
        "free gift card selected winner claim prize enter details click now reward offer",
        "bank account suspended urgent action required verify login credentials immediately",
        "paypal security alert account limited click verify restore access otp password",
        "your account will be closed verify information click link immediately urgent",
        "security breach detected confirm identity login password credentials now urgent",
        "congratulations winner prize claim gift reward free offer click immediately",
        "wire transfer initiated confirm or cancel immediately bank credentials login",
        "unusual login attempt verify account click link password reset security alert",
        "limited time offer claim reward gift prize winner free click now urgent",
        "account suspended verify credentials immediately login password security update",
        "phishing attempt verify paypal login click secure link password otp urgent account",
        "dear user your email account will expire click verify login credentials now",
        "bank fraud alert confirm transaction wire transfer credentials urgent action",
        "your subscription expired click renew now payment credentials update immediately",
        "lottery winner congratulations claim prize gift free reward click link now",
        "identity verification required click link login password confirm credentials urgent",

        # ── LEGITIMATE (label=0) ──
        "meeting scheduled for tomorrow please review the agenda attached team",
        "your order has been shipped tracking number provided delivery expected friday",
        "thank you for your purchase receipt attached for your records order confirmed",
        "quarterly report attached please review before the board meeting presentation",
        "invitation to join team lunch next wednesday please confirm attendance",
        "project update milestone completed ahead of schedule great work team",
        "your subscription has been renewed thank you for staying with us",
        "reminder dentist appointment tomorrow at 3pm please bring insurance card",
        "newsletter this month highlights new features and community updates blog",
        "welcome to the team please complete onboarding by end of week",
        "flight confirmation your booking is confirmed check in opens 24 hours before departure",
        "happy birthday wishing you a wonderful day from all of us celebration",
        "job application received we will review and get back to you soon hiring",
        "your package was delivered left at front door photo attached confirmation",
        "weekly standup notes attached action items for each team member listed",
        "please find attached the invoice for services rendered this month payment due",
        "the document you requested has been shared with you via google drive link",
        "your interview is scheduled for monday at 10am please confirm availability",
        "new comment on your pull request please review the suggested changes github",
        "your annual tax summary is ready to download from the portal this year",
        "team outing planned for friday evening please vote on the activity options",
        "congratulations on your work anniversary five years with the company",
        "the meeting has been rescheduled to thursday at 2pm calendar updated",
        "your library book is due for return next week please renew or return",
        "class assignment due friday please submit via the student portal upload",
        "your health insurance card is ready for download member portal login",
        "new message from your doctor regarding your recent lab results portal",
        "event registration confirmed you are registered for the webinar next week",
        "your electric bill is ready to view online this month usage summary",
        "feedback requested please take a moment to review your recent experience",
    ],
    "label": [1]*30 + [0]*30
}

df = pd.DataFrame(data)

vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=8000, sublinear_tf=True)
X = vectorizer.fit_transform(df["text"])
y = df["label"]

model = LogisticRegression(C=2.0, max_iter=1000)
model.fit(X, y)

print(f"Training accuracy: {model.score(X, y):.2f}")

joblib.dump(model, "spam_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")
print("✅ Models saved!")