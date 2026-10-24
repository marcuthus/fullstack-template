import { NextResponse } from "next/server"

import { handleRouteError } from "@/helpers/auth.helper"
import { configHelper } from "@/helpers/config.helper"
import { signInSchema } from "@/schemas/users/auth.schema"
import { signIn } from "@/services/auth.service"

export async function POST(request: Request) {
    try {
        const body = await request.json()
        const validatedData = signInSchema.parse(body)

        const result = await signIn(validatedData)

        const response = NextResponse.json(result, { status: 200 })

        response.cookies.set("refreshToken", result.refreshToken, {
            httpOnly: true,
            secure: configHelper.isProduction,
            sameSite: "strict",
            maxAge: configHelper.cookie.maxAge,
            path: "/",
        })

        return response
    } catch (error) {
        return handleRouteError(error)
    }
}
