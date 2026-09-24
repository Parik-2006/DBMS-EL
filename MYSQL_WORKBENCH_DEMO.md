# MySQL Workbench Viva Demonstration Guide

This guide provides the exact step-by-step procedure to demonstrate the **MySQL Multi-Database User Isolation** and **Non-Destructive Clear History** architecture during an evaluation or viva.

---

### Prerequisites
1. **Application Running:**  
   Open terminal in `P:\DBMS EL\diploma-project` and run:
   ```cmd
   .\.venv_canonical\Scripts\python.exe manage.py runserver 127.0.0.1:8000
   ```
2. **Browser:** Open Chrome or Edge to `http://127.0.0.1:8000/`.
3. **MySQL Workbench:** Launch MySQL Workbench and connect to your local MySQL 8.0 instance (default port 3306, user `root`).

---

## Step-by-Step Viva Demonstration Walkthrough

### Part 1: Visual Architecture in MySQL Workbench
1. **Open MySQL Workbench** and click your local connection.
2. In the left **Navigator** pane, expand the **SCHEMAS** list.
3. Point out the distinct databases created by our architecture:
   - `maliciousbot_core` (Control Database)
   - `maliciousbot_guest` (Unauthenticated fallback store)
   - `maliciousbot_user_000001` (User `testuser`)
   - `maliciousbot_user_000004` (User `navuser100`)
   - `maliciousbot_user_000005` (User `PARIK`)
   - `maliciousbot_user_000006` (User `e2e_user`)

### Part 2: Show the Control Database Registry
4. In Workbench, execute:
   ```sql
   USE maliciousbot_core;
   SELECT * FROM user_database_registry;
   ```
5. **Explain to the evaluator:**  
   *"Here is the central registry. Notice how database names are deterministic and safe (`maliciousbot_user_000001`). We never use raw user input as a database name to prevent SQL injection and schema namespace corruption."*

### Part 3: Show Physical Data Isolation
6. Open **User A's database** (`maliciousbot_user_000001` - user `testuser`):
   ```sql
   USE maliciousbot_user_000001;
   SELECT id, url, prediction_type, confidence FROM user_maliciousbot;
   SELECT id, status, initial_model FROM pari_scan;
   ```
7. Open **User B's database** (`maliciousbot_user_000004` - user `navuser100`):
   ```sql
   USE maliciousbot_user_000004;
   SELECT id, url, prediction_type, confidence FROM user_maliciousbot;
   SELECT id, status, initial_model FROM pari_scan;
   ```
8. **Point out:**  
   *"User A and User B have completely separate tables and auto-increment sequences. User A has 16 scans, while User B has only 4 scans. There is zero possibility of data leakage across tenants."*

---

### Part 4: Live Demonstration of Dynamic Scan Creation
9. Open the web browser and go to `http://127.0.0.1:8000/login`.
10. Log in as:
    - **Username:** `testuser`
    - **Password:** `TestPassword123!` (or the account's password)
11. Navigate to **Predict** (`/predict`).
12. Enter a test URL:
    ```
    https://viva-demo-test-site.org/portal
    ```
13. Click **ANALYZE URL**.
14. The prediction completes and displays the evaluation result.
15. Switch immediately to MySQL Workbench and run:
    ```sql
    USE maliciousbot_user_000001;
    SELECT * FROM pari_scan ORDER BY id DESC LIMIT 1;
    SELECT * FROM user_maliciousbot ORDER BY id DESC LIMIT 1;
    ```
16. **Show the evaluator:**  
    *"The new scan row was dynamically created inside `maliciousbot_user_000001`. If we check `maliciousbot_user_000004`, this row does not exist."*

---

### Part 5: Non-Destructive "Clear History" Proof
17. In the browser, navigate to the **History** page (`/data`).
18. Show the records in the table, including the newly created scan.
19. Click the red **CLEAR HISTORY** button in the header.
20. A confirmation modal appears stating:  
    *"Your previous scans will be hidden from your History page, but they will NOT be deleted from the database."*
21. Click **CLEAR HISTORY** inside the modal.
22. The page reloads with a success alert:  
    *"History cleared from view. Your records remain stored securely."*  
    The table now displays the empty state: **No Prediction History**.
23. Refresh the page or log out and log back in: the page remains empty!
24. **NOW SWITCH TO MYSQL WORKBENCH TO PROVE ZERO DELETIONS:**
    ```sql
    USE maliciousbot_user_000001;
    -- Count the scans:
    SELECT COUNT(*) AS total_scans_retained FROM pari_scan;
    -- Count the history records:
    SELECT COUNT(*) AS total_history_retained FROM user_maliciousbot;
    -- View the non-destructive boundary marker:
    SELECT * FROM history_clear_events ORDER BY id DESC LIMIT 1;
    ```
25. **Explain to the evaluator:**  
    *"Notice that no rows were deleted! All scans and predictions remain in MySQL. What happened is that a visibility reset marker was inserted into `history_clear_events`. The Django query filters `timestamp > cleared_at`."*

---

### Part 6: "Start From New Records" Demonstration
26. In the browser, go back to **Predict** (`/predict`).
27. Submit a new URL:
    ```
    https://viva-demo-brand-new-scan.com/verify
    ```
28. Click **ANALYZE URL**.
29. Go back to the **History** page (`/data`).
30. **Show the table:**  
    - Exactly **one** record is visible (the new scan `https://viva-demo-brand-new-scan.com/verify`).
    - The old scans remain hidden from the UI.
31. Return to MySQL Workbench and run:
    ```sql
    USE maliciousbot_user_000001;
    SELECT id, url, prediction_type, timestamp FROM user_maliciousbot ORDER BY id ASC;
    ```
32. **Conclude the demonstration:**  
    *"In MySQL, every single scan—both the older scans and the brand new scan—is permanently preserved for regulatory auditing and SOC investigations. Meanwhile, the user gets a fresh view starting from their new records. Furthermore, User B's history view was completely unaffected."*
