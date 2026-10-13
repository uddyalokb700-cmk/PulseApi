from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.core.paginator import Paginator
from rest_framework import generics, permissions
from checks.models import CheckResult
from checks.serializers import CheckResultSerializer
from monitors.models import Monitor


class CheckResultListAPIView(generics.ListAPIView):
    serializer_class = CheckResultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = CheckResult.objects.filter(monitor__owner=self.request.user).select_related('monitor')
        monitor_id = self.request.query_params.get('monitor')
        outcome = self.request.query_params.get('outcome')

        if monitor_id:
            qs = qs.filter(monitor_id=monitor_id)
        if outcome:
            qs = qs.filter(outcome=outcome.lower())

        return qs.order_by('-created_at')


class CheckResultDetailAPIView(generics.RetrieveAPIView):
    serializer_class = CheckResultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return CheckResult.objects.filter(monitor__owner=self.request.user).select_related('monitor')


@method_decorator(login_required, name='dispatch')
class WebChecksHistoryView(View):
    def get(self, request):
        user_monitors = Monitor.objects.filter(owner=request.user)
        monitor_id = request.GET.get('monitor', '')
        outcome = request.GET.get('outcome', '')

        qs = CheckResult.objects.filter(monitor__owner=request.user).select_related('monitor')
        if monitor_id:
            qs = qs.filter(monitor_id=monitor_id)
        if outcome:
            qs = qs.filter(outcome=outcome)

        paginator = Paginator(qs.order_by('-created_at'), 30)
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        return render(request, 'dashboard/checks.html', {
            'page_obj': page_obj,
            'monitors': user_monitors,
            'selected_monitor': monitor_id,
            'selected_outcome': outcome,
        })
