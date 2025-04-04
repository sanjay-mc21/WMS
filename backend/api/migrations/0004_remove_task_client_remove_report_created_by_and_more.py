# Generated by Django 5.0.2 on 2025-03-26 15:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_client_task_client_report'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='task',
            name='client',
        ),
        migrations.RemoveField(
            model_name='report',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='report',
            name='task',
        ),
        migrations.RenameField(
            model_name='task',
            old_name='due_date',
            new_name='date',
        ),
        migrations.RenameField(
            model_name='task',
            old_name='assigned_to',
            new_name='service_engineer',
        ),
        migrations.RemoveField(
            model_name='task',
            name='category',
        ),
        migrations.RemoveField(
            model_name='task',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='task',
            name='is_urgent',
        ),
        migrations.RemoveField(
            model_name='task',
            name='priority',
        ),
        migrations.AddField(
            model_name='task',
            name='cluster',
            field=models.CharField(blank=True, choices=[('Hyderbad-1', 'Hyderbad-1'), ('Hyderbad-2', 'Hyderbad-2'), ('Kurnool', 'Kurnool'), ('Tirupathi', 'Tirupathi'), ('Warangal', 'Warangal')], max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='task',
            name='global_id',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='task',
            name='service_type',
            field=models.CharField(choices=[('Full Service', 'Full Service'), ('TOP UP', 'TOP UP')], default='Full Service', max_length=20),
        ),
        migrations.AddField(
            model_name='task',
            name='site_name',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='task',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='task',
            name='title',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.DeleteModel(
            name='Client',
        ),
        migrations.DeleteModel(
            name='Report',
        ),
    ]
