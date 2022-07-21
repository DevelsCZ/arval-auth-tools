<?php

namespace DevelsCz\ArvalAuthTools;

use App\Exceptions\ApiException;
use App\Models\Company;
use App\Models\Role;
use App\Models\User;
use App\Services\Environment;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Session;

class ArvalAuthService
{
    /**
     * @param string $email
     * @param string $password
     * @return User|null
     * @throws AuthenticationException
     */
    public function login(string $email, string $password): ?User
    {
        $apiResponse = Http::withHeaders(['X-Auth' => config('arvalAuth.token')])
            ->withBody(
                json_encode([
                    'email' => $email,
                    'password' => $password,
                ]),
                'application/json'
            )
            ->post(
                sprintf('%s/api/v1/auth/login', config('arvalAuth.domains.' . Environment::getEnv()))
            )
        ;
        /**
         * @var GuzzleHttp\Psr7\Response $apiResponse
         */
        $responseBody = json_decode($apiResponse->body());
        if(!$responseBody->success) {
            return null;
        }

        // get/create local user entity
        $user = User::whereRaw('LOWER(email) = LOWER(?)', $email)->first();
		$companyID = null;
		// not present in some projects
		if(class_exists(Company::class)) {
        	$companyID = Company::where('slug', $responseBody->user->company ?: 'arval')->value('id');
		}

        if(!$user) {
            $user = new User([
                'email' => strtolower($email),
                'password' => Hash::make($password),
            ]);
			if($companyID) {
				$user->company_id = $companyID;
			}
        }

        // update user with provided credentials
        $user->update([
            'firstname' => $responseBody->user->firstname,
            'lastname' => $responseBody->user->lastname,
            'phone' => $responseBody->user->phone,
            'degree_before' => $responseBody->user->degreeBefore,
            'degree_after' => $responseBody->user->degreeAfter,
        ]);
		if($companyID) {
			$user->update([
            	'company_id' => $companyID,
			]);
		}
		$user->save();

        $appCode = config('arvalAuth.appCode');
		$roleCode = $responseBody->user->roles->$appCode;
		if($roleCode == 'banned') {
			return null;
		}

        $user->assignRole(Role::where('name', $roleCode)->first());

        return $user;
    }

    /**
     * @param User $user
     * @return void|null
     */
    public function updateUser(User $user): bool
    {
        $apiResponse = Http::withHeaders(['X-Auth' => config('arvalAuth.token')])
            ->withBody(
                json_encode([
                    'email' => $user->email,
                    'firstname' => $user->firstname,
                    'lastname' => $user->lastname,
                    'degreeBefore' => $user->degree_before,
                    'degreeAfter' => $user->degree_after,
                    'phone' => $user->phone,
                    'role' => $user->roles()->value('name'),
                ]),
                'application/json'
            )
            ->patch(
                sprintf('%s/api/v1/user', config('arvalAuth.domains.' . Environment::getEnv()))
            )
        ;
        /**
         * @var GuzzleHttp\Psr7\Response $apiResponse
         */
        $responseBody = json_decode($apiResponse->body());
        if($apiResponse->status() != 200 || !$responseBody->success) {
            flash('Invalid response from arval-auth API.')->error();
            return false;
        }
        return $responseBody->success;
    }

	/**
	 * @param callable|null $callback
	 * @return JsonResponse
	 */
    public function deleteUser(Callable $callback = null): JsonResponse
    {
		$user = User::whereRaw('LOWER(email) = LOWER(?)', [request('email')])->first();
		if(!$user) {
			return response()->json(['success' => false, 'error' => 'User not found.']);
		}
        $user->delete();
		if($callback) {
			$callback($user);
		}
		return response()->json(['success' => true, 'error' => null]);
    }

    /**
     * @param User $user
     * @param string $oldPassword
     * @param string $newPassword
     * @return bool|null
     * @throws ApiException
     */
    public function updatePassword(User $user, string $oldPassword, string $newPassword): ?bool
    {
        $apiResponse = Http::withHeaders(['X-Auth' => config('arvalAuth.token')])
            ->withBody(
                json_encode([
                    'email' => $user->email,
                    'oldPassword' => $oldPassword,
                    'newPassword' => $newPassword,
                ]),
                'application/json'
            )
            ->post(
                sprintf('%s/api/v1/auth/change-password', config('arvalAuth.domains.' . Environment::getEnv()))
            )
            ->onError(function($response) {
				report($response->__toString());
                dd($response);
            });
        ;
        /**
         * @var GuzzleHttp\Psr7\Response $apiResponse
         */
        if($apiResponse->status() != 200) {
            throw new ApiException('Invalid response from arval-auth API.');
        }
        $responseBody = json_decode($apiResponse->body());
        if($responseBody->error) {
            throw new ApiException($responseBody->error);
        }
        if(!$responseBody->success) {
            throw new ApiException('Invalid username and/or password.');
        }
        return $responseBody->success;
    }

	/**
	 * @param User $user
	 * @return bool|null
	 */
    public function refreshUser(User $user): ?bool
    {
        $apiResponse = Http::withHeaders(['X-Auth' => config('arvalAuth.token')])
            ->get(
                sprintf(
					'%s/api/v1/user/%s',
					config('arvalAuth.domains.' . Environment::getEnv()),
					urlencode($user->email)
				),
            )
            ->onError(function($response) {
				report($response->__toString());
                dd($response);
            })
        ;
        /**
         * @var GuzzleHttp\Psr7\Response $apiResponse
         */
        if($apiResponse->status() != 200) {
            throw new ApiException('Invalid response from arval-auth API.');
        }
        $responseBody = json_decode($apiResponse->body());
        if($responseBody->error) {
            throw new ApiException($responseBody->error);
        }
        if(!$responseBody->success) {
            throw new ApiException('Unable to load user data from arval-auth API.');
        }

		$user->update([
			'firstname' => $responseBody->user->firstname,
			'lastname' => $responseBody->user->lastname,
			'degree_before' => $responseBody->user->degreeBefore,
			'degree_after' => $responseBody->user->degreeAfter,
			'phone' => $responseBody->user->phone,
		]);
		// not present in some projects
		if(class_exists(Company::class)) {
			$user->update([
				'company_id' => Company::where('slug', $responseBody->user->company)->value('id'),
			]);
		}

        return $responseBody->success;
    }

	/**
	 * @param User $user
	 * @return bool|null
	 */
    public function createUser(User $user, string $rawPassword): ?bool
    {
        $apiResponse = Http::withHeaders(['X-Auth' => config('arvalAuth.token')])
			->withBody(
				json_encode([
					'firstname' => $user->firstname,
					'lastname' => $user->lastname,
					'email' => $user->email,
					'degreeBefore' => $user->degree_before,
					'degreeAfter' => $user->degree_after,
					'phone' => $user->phone,
					'role' => $user->roles()->value('name'),
					'company' => optional($user->company)->slug ?: 'arval',
					'password' => $rawPassword,
				]),
				'application/json'
			)
            ->post(
                sprintf(
					'%s/api/v1/user',
					config('arvalAuth.domains.' . Environment::getEnv())
				),
            )
            ->onError(function($response) {
				report($response->__toString());
                dd($response);
            })
        ;
        /**
         * @var GuzzleHttp\Psr7\Response $apiResponse
         */
        if($apiResponse->status() != 201) {
            throw new ApiException('Invalid response from arval-auth API.');
        }
        $responseBody = json_decode($apiResponse->body());
        if($responseBody->error) {
            throw new ApiException($responseBody->error);
        }
        if(!$responseBody->success) {
            throw new ApiException('Unable to load user data from arval-auth API.');
        }

		// not present in some projects
		if(class_exists(Company::class)) {
			$user->update([
				'company_id' => Company::where('slug', $responseBody->user->company)->value('id'),
			]);
		}

        return $responseBody->success;
    }

    /**
     * @param string $afterLoginUrl
     * @return User
     */
    public function loginUsingLink(string $afterLoginUrl): User
    {
        $email = urldecode(request('email', ''));
        $token = urldecode(request('clientLoginToken', ''));
        if(!$email) {
            dd('Missing parameter: email');
        }
        if(!$token) {
            dd('Missing parameter: clientLoginToken');
        }

		$expectedToken = $this->createClientLoginToken($email);
		if($token != $expectedToken) {
			dd('Invalid token/email combination.');
		}

		$user = User::whereRaw('LOWER(email) = LOWER(?)', [$email])->first();
		$guard = Auth::guard('web');
		$guard->logout();
		Session()->flush();
		$guard->login($user);
		return Redirect::away($afterLoginUrl);
    }

    /**
     * @return JsonResponse
     */
    public function logout(): JsonResponse
    {
        $email = urldecode(request('email', ''));
        if(!$email) {
            return response()->json(['success' => false, 'error' => 'Please provide "email" parameter in URL.']);
        }
        $user = User::whereRaw('LOWER(email) = LOWER(?)', [$email])->first();
        if($user) {
            $user->update([
                'remember_token' => null,
            ]);
            DB::table('sessions')->where('user_id', $user->id)->delete();
        }
        return response()->json(['success' => true]);
    }

    /**
     * @return \Illuminate\Http\RedirectResponse
     */
    public function redirectToForgottenPasswordPage(): RedirectResponse
    {
        $returnUrl = route('login');
        $arvalAuthPage = sprintf('%s?returnUrl=%s', config('arvalAuth.forgottenPasswordUrl.' . Environment::getEnv()), urlencode($returnUrl));
        return Redirect::away($arvalAuthPage);
    }

	/**
	 * @param $email
	 * @return string
	 */
	private function createClientLoginToken($email): string
	{
		return md5(sha1(sprintf(
			'%s|%s',
			config('arvalAuth.loginKey'),
			mb_strtolower(trim($email))
		)));
	}
}
