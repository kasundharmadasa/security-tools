from django.conf.urls import url

from dojo.test import views

urlpatterns = [
    #  tests
    url(r'^calendar/tests$', views.test_calendar, name='test_calendar'),
    url(r'^test/(?P<tid>\d+)$', views.view_test,
        name='view_test'),
    url(r'^test/(?P<tid>\d+)/ics$', views.test_ics,
        name='test_ics'),
    url(r'^test/(?P<tid>\d+)/edit$', views.edit_test,
        name='edit_test'),
    url(r'^test/(?P<tid>\d+)/delete$', views.delete_test,
        name='delete_test'),
    url(r'^test/(?P<tid>\d+)/add_findings$', views.add_findings,
        name='add_findings'),
    url(r'^test/(?P<tid>\d+)/bulk', views.finding_bulk_update,
        name='finding_bulk_update'),
    url(r'^test/(?P<tid>\d+)/add_findings/(?P<fid>\d+)$',
        views.add_temp_finding, name='add_temp_finding'),
    url(r'^test/(?P<tid>\d+)/note/(?P<nid>\d+)/delete$',
        views.delete_test_note, name='delete_test_note'),
    url(r'^test/(?P<tid>\d+)/search$', views.search, name='search'),
    url(r'^test/(?P<tid>\d+)/re_import_scan_results', views.re_import_scan_results, name='re_import_scan_results'),
    url(r'^test/(?P<tid>\d+)/download_cvffv1$', views.download_cvffv1_test,
        name='download_cvffv1_test'),
    url(r'^test/(?P<tid>\d+)/download_multi_usage_cvffv1$', views.download_multi_usage_cvffv1_test,
        name='download_multi_usage_cvffv1_test'),
]
