import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import User from 'App/Models/User'

export default class AuthController {
  public redirect({ ally }: HttpContextContract) {
    return ally.use('discord').redirect()
  }

  public async callback({ ally, auth, response }: HttpContextContract) {
    const discord = ally.use('discord')

    /**
     * User has explicitly denied the login request
     */
    if (discord.accessDenied()) {
      return 'Access was denied'
    }

    /**
     * Unable to verify the CSRF state
     */
    if (discord.stateMisMatch()) {
      return 'Request expired. Retry again'
    }

    /**
     * There was an unknown error during the redirect
     */
    if (discord.hasError()) {
      return discord.getError()
    }

    /**
     * Finally, access the user
     */
    const discordUser = await discord.user()

    const user = await User.updateOrCreate(
      {
        email: discordUser.email!,
      },
      {
        email: discordUser.email!,
        username: discordUser.name,
        avatarUrl: discordUser.avatarUrl,
        discordId: discordUser.id,
        accessToken: discordUser.token.token,
      }
    )

    /**
     * Login user using the web guard
     */
    await auth.use('web').login(user)
    return response.redirect('/')
  }

  public async logout({ auth, response }: HttpContextContract) {
    await auth.use('web').logout()
    return response.redirect('/login')
  }
}
