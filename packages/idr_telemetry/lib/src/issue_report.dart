import 'dart:io';

import 'redact.dart';

/// Email issue reporting (docs/observability/04 §4.2a, D15), shared by the Target app and the CLIs:
/// the program only prepares a bundle and a prefilled `mailto:` message; the user attaches the
/// ZIP and sends it. The recipient lives here and nowhere else.
const reportRecipient = 'dev10@advcomm.ca';
const maxLinkChars = 1800;
const maxDescriptionChars = 2000;

String reportSubject(String reportId) => 'IDR issue report $reportId';

/// Fixed block under the user's text: public-class values only (04 §5.1).
String reportDetails({
  required String reportId,
  required String zipName,
  required int zipBytes,
  required String appVersion,
  required String flavor,
}) =>
    'App: $appVersion ($flavor)\n'
    'OS: ${Platform.operatingSystem} ${Platform.operatingSystemVersion}\n'
    'Report ID: $reportId\n'
    'Attachment: $zipName (${(zipBytes / 1024).round()} KiB)\n\n'
    'Please attach the ZIP file named above.';

/// The plain-text message the user can also copy: description (redacted, truncated to fit
/// the link) + details. The full description stays in the bundle manifest.
String reportBody({required String description, required String details, required String reportId}) {
  final text = redact(description.trim());
  String compose(String t) => '$t\n\n---\n$details';
  var body = compose(text);
  var link = mailtoLink(reportSubject(reportId), body);
  if (link.length <= maxLinkChars) return body;
  const note = '… (truncated; full text in the ZIP)';
  var keep = text.length;
  while (keep > 0 && link.length > maxLinkChars) {
    keep = keep > 200 ? keep - 100 : keep - 10;
    if (keep < 0) keep = 0;
    body = compose('${text.substring(0, keep)}$note');
    link = mailtoLink(reportSubject(reportId), body);
  }
  return body;
}

/// `mailto:` with %20-encoded spaces (some clients show `+` literally).
String mailtoLink(String subject, String body) =>
    'mailto:$reportRecipient?subject=${Uri.encodeComponent(subject)}&body=${Uri.encodeComponent(body)}';
