# HMYshop

HMYshop is a web-based shop management application built with **Python Flask and MySQL**. It is designed to help small businesses manage their day-to-day shop operations through a simple web interface.

## Features

* Shop management
* Product management
* Customer management
* Sales and transaction management
* Inventory management
* Database-driven records
* Search and data management
* Web-based interface
* MySQL database integration

## Technologies Used

* **Python**
* **Flask**
* **MySQL**
* **HTML**
* **CSS**
* **JavaScript**
* **Jinja2**

## Project Structure

```text
HMYshop/
│
├── app.py
├── sqlconnection.py
├── schema.sql
├── templates/
├── static/
├── uploads/
├── logs/
├── test.py
├── .env
├── .gitignore
└── README.md
```

## Requirements

Before running the project, make sure you have:

* Python 3.x
* MySQL Server
* pip

Install the required Python packages:

```bash
pip install -r requirements.txt
```

If `requirements.txt` has not been created yet:

```bash
pip freeze > requirements.txt
```

## Environment Configuration

Create a `.env` file in the project root and configure the required environment variables.

Example:

```env
DB_HOST=localhost
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=your_database
SECRET_KEY=your_secret_key
```

> Do not commit `.env` to GitHub. It contains local configuration and sensitive information.

## Database Setup

Create a MySQL database for HMYshop.

Then import the database schema:

```bash
mysql -u your_username -p your_database < schema.sql
```

You can also import `schema.sql` using MySQL Workbench.

After creating the database, configure the database credentials in your `.env` file.

## Running the Application

Clone the repository:

```bash
git clone <repository-url>
```

Enter the project directory:

```bash
cd HMYshop
```

Create a virtual environment:

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Configure the `.env` file and MySQL database.

Run the application:

```bash
python app.py
```

The application can then be accessed through the local Flask server.

## Development

During development, the Flask development server can be used.

For production deployment, a production WSGI server such as Gunicorn can be used with Nginx.

Example:

```bash
gunicorn app:app
```

## Security

Sensitive and generated files should not be committed to the repository.

The `.gitignore` file is configured to exclude files such as:

```text
.env
logs/
uploads/
__pycache__/
*.pyc
instance/
```

Never commit:

* Database passwords
* Secret keys
* API keys
* Private credentials
* Real customer data
* Production configuration containing secrets

## Database

The database schema is maintained in:

```text
schema.sql
```

Database credentials should be provided through environment variables rather than being hard-coded in the application.

## Testing

Development tests can be run using:

```bash
python test.py
```

## Future Improvements

Possible future improvements include:

* Advanced inventory management
* Sales and purchase reports
* Improved dashboard
* Invoice generation
* User roles and permissions
* Automated backups
* Better analytics
* Production deployment
* Mobile-friendly interface

## License

This project is currently intended for development and educational use.

A suitable open-source license can be added if the project is released publicly.
