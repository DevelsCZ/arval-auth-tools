<?php

namespace App\Services;

use App\Exceptions\ApiException;
use App\Models\Company;
use App\Models\Role;
use App\Models\User;
use http\Env;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
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
        $company = Company::where('slug', $responseBody->user->company ?: 'arval')->firstOrFail();
        if(!$user) {
            $user = new User([
                'email' => strtolower($email),
                'password' => Hash::make($password),
                'company_id' => $company->id,
            ]);
        }

        // update user with provided credentials
        $user->update([
            'firstname' => $responseBody->user->firstname,
            'lastname' => $responseBody->user->lastname,
            'phone' => $responseBody->user->phone,
            'degree_before' => $responseBody->user->degreeBefore,
            'degree_after' => $responseBody->user->degreeAfter,
            'company_id' => $company->id,
        ]);
        $appCode = config('arvalAuth.appCode');
        $role = Role::where('name', $responseBody->user->roles->$appCode)->first();
        $user->assignRole($role);

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
}
