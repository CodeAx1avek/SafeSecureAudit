# Generated by Django 5.0.3 on 2024-11-07 08:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0005_alter_scan_tool_used_delete_tool'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='ip_address',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
    ]
