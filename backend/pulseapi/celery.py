import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pulseapi.settings')

app = Celery('pulseapi')

# Load task configuration from Django settings with 'CELERY_' prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Celery Debug Request: {self.request!r}')
