Notification: {{ $template }}
@foreach ($context as $key => $value)
{{ $key }}: {{ is_scalar($value) ? $value : json_encode($value) }}
@endforeach
