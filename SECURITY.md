# אבטחה - Security Configuration

## GitHub Secrets שכדאי להגדיר:

### חובה (Required):
- `POSTGRES_PASSWORD` - סיסמה למסד הנתונים
- `SECRET_KEY` - מפתח הצפנה ל-Flask sessions

### מומלץ (Recommended):
- `POSTGRES_USER` - שם משתמש למסד הנתונים
- `POSTGRES_DB` - שם מסד הנתונים
- `GF_SECURITY_ADMIN_PASSWORD` - סיסמת admin ל-Grafana

### אופציונלי (Optional - for Docker Hub):
- `DOCKER_HUB_USERNAME` - שם משתמש בדוקר האב
- `DOCKER_HUB_TOKEN` - טוקן גישה לדוקר האב

## הגדרת Secrets ב-GitHub:

1. עבור לעמוד הפרויקט ב-GitHub
2. Settings → Secrets and variables → Actions
3. לחץ על "New repository secret"
4. הוסף כל אחד מהמשתנים לעיל

## הרצה מקומית:

צור קובץ `.env` בתיקיית הפרויקט:
```bash
cp .env.example .env
```

ערוך את הקובץ עם הערכים שלך.

## פורטים חשופים:

בסביבת פיתוח מקומית:
- 80 - אפליקציה ראשית
- 3000 - Grafana (admin/[GF_SECURITY_ADMIN_PASSWORD])
- 9090 - Prometheus

**הערה**: בסביבת production, כדאי לחסום את פורטי הניטור (3000, 9090) מגישה חיצונית.