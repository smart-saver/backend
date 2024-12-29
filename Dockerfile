# Use an official Python runtime as a parent image
FROM python:3.9

# Set environment variables (adjust as needed)
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE myapp.settings
ENV IS_DEBUG_MODE false

# Create and set the working directory
RUN mkdir /app
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install project dependencies
RUN pip install -r requirements.txt

ENV XYZ 1
# Copy the rest of the application code into the container
COPY . /app/

# Expose the port that your Django app will run on (adjust if needed)
EXPOSE 8000

# Run the Django development server (adjust as needed)
CMD ["python", "manage.py", "runserver", "--insecure", "0.0.0.0:8000"]