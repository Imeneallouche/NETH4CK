# NetH4cK

## Steps

```bash
pip3 install virtualenv

virtualenv env

source env/bin/activate

pip3 install flask flask-sqlalchemy
```



## Hierarchy of the repository
```
NETH4CK/                # main project directory
├── env                 # virtual environment folder (created on activation)
├── app/                # Application logic
│   ├── __init__.py     # Empty file to mark app as a Python package
│   ├── models.py       # Database models defined here (if applicable)
│   ├── forms.py        # Forms for user input (if applicable)
│   ├── views.py        # Flask routes and view functions defined here
│   └── utils.py        # Utility functions used throughout the app
├── config.py           # Project configuration (database connection, secret keys)
├── templates/          # HTML templates
│   ├── base.html       # Base template with layout for all pages
│   ├── index.html      # Homepage template
│   └── ...             # Additional templates for other pages
├── static/             # Static files (CSS, JS, images)
│   ├── css/            # Stylesheets
│   ├── js/             # JavaScript files (if applicable)
│   └── images/         # Static images used in the app
├── requirements.txt    # List of dependencies needed for the project
├── Procfile            # Heroku process configuration (optional)
├── runtime.txt         # Heroku runtime environment (optional)
└── main.py             # Application entry point (Flask app creation)
```
