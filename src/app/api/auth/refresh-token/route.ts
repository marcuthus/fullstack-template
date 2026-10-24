import { cookies } from "next/headers"
import { NextResponse } from "next/server"

import { handleRouteError } from "@/helpers/auth.helper"
import { configHelper } from "@/helpers/config.helper"
import { refreshTokenSchema } from "@/schemas/users/auth.schema"
import { refresh } from "@/services/auth.service"

export async function POST(request: Request) {
    try {
        let refreshToken: string | undefined

        try {
            const body = await request.json()
            const validatedData = refreshTokenSchema.parse(body)
            refreshToken = validatedData.refreshToken
        } catch {
            const cookieStore = await cookies()
            refreshToken = cookieStore.get("refreshToken")?.value
        }

        if (!refreshToken) {
            return NextResponse.json({ message: "Refresh token is required" }, { status: 400 })
        }

        const result = await refresh(refreshToken)

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
