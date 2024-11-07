from django.contrib import admin, messages
from django.db.models import Count
from .models import Scan, BlockedIP

class MostUsedIPFilter(admin.SimpleListFilter):
    title = 'Most Used IPs'  # Title shown in the filter sidebar
    parameter_name = 'most_used_ip'

    def lookups(self, request, model_admin):
        # Get the most used IPs by counting occurrences and ordering them in descending order
        most_used_ips = (
            Scan.objects.values('ip_address')
            .annotate(ip_count=Count('ip_address'))
            .order_by('-ip_count')[:10]  # Get top 10 most used IPs
        )
        # Create a tuple of (ip_address, display_name) for each IP
        return [(ip['ip_address'], f"{ip['ip_address']} ({ip['ip_count']} uses)") for ip in most_used_ips]

    def queryset(self, request, queryset):
        # Filter queryset based on selected IP address in the filter
        if self.value():
            return queryset.filter(ip_address=self.value())
        return queryset

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('user', 'domain_name', 'tool_used', 'ip_address', 'timestamp')  # Display IP address
    list_filter = ('tool_used', 'user', MostUsedIPFilter)  # Include the IP usage filter
    actions = ['delete_anonymous_scans', 'block_ip']  # Add block_ip action

    def delete_anonymous_scans(self, request, queryset):
        # Action to delete all anonymous user scans
        anonymous_scans = Scan.objects.filter(user__isnull=True)
        count = anonymous_scans.count()
        anonymous_scans.delete()
        self.message_user(request, f"Deleted {count} scans made by anonymous users.")
    delete_anonymous_scans.short_description = "Delete all anonymous user scans"

    def block_ip(self, request, queryset):
        # Action to block IPs from selected scans
        blocked_ips = []
        for scan in queryset:
            if scan.ip_address:
                # Create or get an entry in BlockedIP for each unique IP
                blocked_ip, created = BlockedIP.objects.get_or_create(ip_address=scan.ip_address)
                if created:
                    blocked_ips.append(scan.ip_address)

        # Check if any IPs were actually blocked and create a custom message
        if blocked_ips:
            message = f"Successfully blocked {len(blocked_ips)} IP(s): " + ", ".join(blocked_ips)
            self.message_user(request, message, level=messages.SUCCESS)
        else:
            self.message_user(request, "All selected IPs were already blocked.", level=messages.WARNING)
    block_ip.short_description = "Block selected IP addresses"

    def changelist_view(self, request, extra_context=None):
        # Add additional context for the changelist view
        total_logged_in_visits = Scan.objects.filter(user__isnull=False).count()
        total_anonymous_visits = Scan.objects.filter(user__isnull=True).count()

        # Calculate most used tool
        most_used_tool = (
            Scan.objects.values('tool_used')
            .annotate(tool_count=Count('tool_used'))
            .order_by('-tool_count')
            .first()
        )
        most_used_tool_name = most_used_tool['tool_used'] if most_used_tool else "N/A"
        most_used_tool_count = most_used_tool['tool_count'] if most_used_tool else 0

        # Calculate most used IP
        most_used_ip = (
            Scan.objects.values('ip_address')
            .annotate(ip_count=Count('ip_address'))
            .order_by('-ip_count')
            .first()
        )
        most_used_ip_address = most_used_ip['ip_address'] if most_used_ip else "N/A"
        most_used_ip_count = most_used_ip['ip_count'] if most_used_ip else 0

        # Pass the calculated values to the context
        extra_context = extra_context or {}
        extra_context['total_logged_in_visits'] = total_logged_in_visits
        extra_context['total_anonymous_visits'] = total_anonymous_visits
        extra_context['most_used_tool_name'] = most_used_tool_name
        extra_context['most_used_tool_count'] = most_used_tool_count
        extra_context['most_used_ip_address'] = most_used_ip_address
        extra_context['most_used_ip_count'] = most_used_ip_count

        return super().changelist_view(request, extra_context=extra_context)

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'blocked_at')
    search_fields = ('ip_address', 'reason')
