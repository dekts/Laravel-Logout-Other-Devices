# Laravel Force Logged Out From Other Devices
Logout Other Devices

## STEP 1: DB FIELDS MODIFICATION

> Add two field in user table called `jwt_auth_token` type *string* and `should_logout_from_mobile` type *integer* `[0,1]`

> Here I have used `[0,1]` flag for checking the existing logged in user.

## STEP 2: WRITE CODE FOR API

> I have used JWT Auth to authenticate the users. so when user login in the application at that time we have to store the auth token in the database for that specific user

```php
<?php

$credentials = [
    'email' => $request->email,
    'password' => $request->password
];

if (!$token = auth('api')->attempt($credentials)) {
    return response()->json([
        'message' => trans('common_messages.auth.invalid_credential')
    ], 422);
}

$user = User::whereEmail(request('email'))->first();

if ($user) {
    if($user->should_logout_from_mobile === 1) {
        return response()->json([
            'message' => trans('common_messages.auth.other_login'), 'id' => $user->id
        ], 422);
    }

    $user->should_logout_from_mobile = 1;
    $user->jwt_auth_token = $token;
    
    if($user->save()) {

        return $this->respond([
            'message' => trans('common_messages.auth.login_in'),
            'token'   => $token,
            'user'    => $user
        ]);

    } else {

        return response()->json([
            'message' => trans('common_messages.auth.wrong')
        ], 422);
    }

} else {

    return response()->json([
        'message' => trans('common_messages.auth.unauthorized_for_mobile')
    ], 422);
}
```

> Now let me explain above code small part which is important

```php
if($user->should_logout_from_mobile === 1) {
    return response()->json([
        'message' => trans('common_messages.auth.other_login'), 'id' => $user->id
    ], 422);
}
```

> Above code will check for logged in user in mobile if it's value 1 then we have to show a message with user ID

> The user ID through we can call another API which is flush the record of token and flag.

```php
public function logoutFromDevice(Request $request)
{
    try {

        if ($request->id) {

            $user = User::find($request->id);

            $user->should_logout_from_mobile = 0;
            $user->jwt_auth_token = null;

            if ($user->save()) {

                return $this->respond([
                    'message' => trans('common_messages.auth.logged_out_from_devices')
                ]);
            }

        } else {

            return $this->respond([
                'message' => trans('common_messages.auth.invalid_request')
            ], 422);
        }

    } catch(\Exception $e) {

        return $this->respond([
            'message' => $e->getMessage()
        ], 500);
    }
}
```

> In above code will work after message we will provide a user for option to logged out from other devices or not. If click on yes then above method will execute and flush the token and flag.

## STEP 3: CREATE MIDDLEWARE FOR ROUTE AND IT'S SETTINGS

```php
<?php

namespace App\Http\Middleware;

use Closure;
use App\Models\User\User;

class ForceLoggedOut
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $apiToken = null)
    {
        $apiToken= getBearerToken(); // token or whatever you sending key as

        $canAccess = false;
        if ($apiToken) {
            foreach(User::all() as $user) {
                if($user->jwt_auth_token == $apiToken) {
                    $canAccess = true;
                }
            }
        }

        if($canAccess == false) {
            return response()->json([
                'message' => trans('common_messages.auth.access_denied')
            ], 422);
            // abort(403, 'Access denied');
        }
        return $next($request);
    }
}
```

> In `Kernel.php` add below line to execute the middleware

```php
protected $routeMiddleware = [
    .....
    .....
    'force-logged-out' => \App\Http\Middleware\ForceLoggedOut::class,
];
```

## STEP 4: ROUTE SETTNGS

> Here we will add our middleware for prevent the user to access the routes.

```php

Route::group(['middleware' => ['jwt.auth', 'force-logged-out']],function (){
    .......
    .......
    .......
});
```

### PLEASE CONTRIBUTE YOUR IDEAS TO MAKE ABOVE CODE MORE RELIBLE

## PR ALWAYS WELCOM

# CHEERS!
