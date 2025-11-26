# Password Scorer - מחשבון חוזק סיסמה

מערכת מתקדמת לבדיקת חוזק סיסמאות עם בינה מלאכותית, ניטור וגנרציה חכמה של סיסמאות.

## 🚀 תכונות

- **בדיקת חוזק סיסמה** - באמצעות מודל ML מאומן
- **גנרציה חכמה** - יצירת סיסמאות מבוססת על דפוסים אישיים
- **אותנטיקציה** - מערכת משתמשים עם הפרדת נתונים
- **ניטור מתקדם** - Prometheus + Grafana
- **היסטוריה אישית** - מעקב אחר סיסמאות קודמות

## 🏗️ ארכיטקטורה

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Frontend  │────│    NGINX    │────│   Backend   │
│   (HTML/JS) │    │ (Proxy/LB)  │    │  (Flask)    │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                   ┌─────────────┐    ┌─────────────┐
                   │  Prometheus │    │ PostgreSQL  │
                   │ (Metrics)   │    │ (Database)  │
                   └─────────────┘    └─────────────┘
                           │
                   ┌─────────────┐
                   │   Grafana   │
                   │(Dashboards) │
                   └─────────────┘
```

## 🛠️ הפעלה מקומית

```bash
# שכפול הפרויקט
git clone <repository-url>
cd password-scorer

# הפעלת המערכת
docker-compose up -d

# גישה לשירותים
# אפליקציה: http://localhost
# Grafana: http://localhost:3000 (admin/admin123)
# Prometheus: http://localhost:9090
```

## 🧪 הרצת בדיקות

```bash
cd backend
pip install -r requirements.txt
python -m pytest tests/ -v
```

## 📊 ניטור

- **Prometheus**: איסוף מדדי ביצועים
- **Grafana**: דאשבורדים ויזואליים
- **מדדים זמינים**:
  - מספר בקשות לכל endpoint
  - זמני תגובה
  - התפלגות חוזק סיסמאות
  - פעולות דאטה בייס

## 🔐 אבטחה

- סיסמאות מוצפנות ב-SHA256
- הפרדת נתונים בין משתמשים
- Session-based authentication
- הגנה מפני גישה לא מורשית

## 🚀 CI/CD

הפרויקט כולל GitHub Actions pipeline שמריץ:
- בדיקות יחידה
- בדיקות אינטגרציה
- בניית Docker images
- בדיקות אבטחה

## 📝 רישיון

MIT License