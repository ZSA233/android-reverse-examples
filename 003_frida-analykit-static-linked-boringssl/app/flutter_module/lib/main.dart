import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:flutter/services.dart';

const _chan = MethodChannel('com.frida_analykit.static_linked_boringssl-demo');

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  _chan.setMethodCallHandler((call) async {
    if (call.method == 'performRequest') {
      final args = Map<String, dynamic>.from(call.arguments);
      final url = args['url'] as String;
      final userAgent = args['userAgent'] as String? ??
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15";
      try {
        final resp = await http.get(
            Uri.parse(url),
          headers: {
              'User-Agent': userAgent,
              'X': "Dart",
          }
        );
        return '[Dart] OK - code[${resp.statusCode}]: ${resp.body.length} bytes';
      } catch (e) {
        return '[Dart] ERROR - $e';
      }
    }
    throw PlatformException(
      code: 'Unimplemented',
      message: 'Method ${call.method} not implemented',
    );
  });

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return const SizedBox.shrink();
  }
}