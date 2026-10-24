import { beforeEach, describe, expect, it, vi } from "vitest"

import { prisma } from "../../helpers/prisma.helper"
import * as jwtUtil from "../../utils/jwt.util"
import * as passwordUtil from "../../utils/password.util"
import { refresh, signIn, signUp } from "../auth.service"

// Mock prisma and utilities
vi.mock("../../helpers/prisma.helper", () => ({
    prisma: {
        user: {
            findFirst: vi.fn(),
            findUnique: vi.fn(),
            create: vi.fn(),
        },
    },
}))

vi.mock("../../utils/jwt.util", () => ({
    generateAccessToken: vi.fn(),
    generateRefreshToken: vi.fn(),
    verifyToken: vi.fn(),
}))

vi.mock("../../utils/password.util", () => ({
    hashPassword: vi.fn(),
    comparePassword: vi.fn(),
}))

describe("AuthService", () => {
    beforeEach(() => {
        vi.clearAllMocks()
    })

    describe("signUp", () => {
        it("should successfully create a new user when everything is valid", async () => {
            const signUpData = {
                name: "John Doe",
                email: "john@example.com",
                username: "johndoe",
                password: "password123",
            }

            vi.mocked(prisma.user.findFirst).mockResolvedValue(null)
            vi.mocked(passwordUtil.hashPassword).mockResolvedValue("hashed_password")
            vi.mocked(prisma.user.create).mockResolvedValue({
                id: "user-id",
                ...signUpData,
                password: "hashed_password",
                role: "USER",
                apiKey: "api_key",
                createdAt: new Date(),
                updatedAt: new Date(),
            } as any)

            const result = await signUp(signUpData)

            expect(prisma.user.findFirst).toHaveBeenCalledWith({
                where: {
                    OR: [{ email: signUpData.email }, { username: signUpData.username }],
                },
            })
            expect(passwordUtil.hashPassword).toHaveBeenCalledWith("password123")
            expect(prisma.user.create).toHaveBeenCalled()
            expect(result).not.toHaveProperty("password")
            expect(result.username).toBe("johndoe")
        })

        it("should throw error if user already exists", async () => {
            const signUpData = {
                name: "John Doe",
                email: "john@example.com",
                username: "johndoe",
                password: "password123",
            }

            vi.mocked(prisma.user.findFirst).mockResolvedValue({ id: "existing-user" } as any)

            await expect(signUp(signUpData)).rejects.toThrow("Usuário ou e-mail já cadastrado")
        })
    })

    describe("signIn", () => {
        it("should return tokens and user on successful sign in", async () => {
            const signInData = {
                username: "johndoe",
                password: "password123",
            }

            const user = {
                id: "user-id",
                name: "John Doe",
                username: "johndoe",
                email: "john@example.com",
                password: "hashed_password",
                role: "USER",
            }

            vi.mocked(prisma.user.findUnique).mockResolvedValue(user as any)
            vi.mocked(passwordUtil.comparePassword).mockResolvedValue(true)
            vi.mocked(jwtUtil.generateAccessToken).mockReturnValue("access_token")
            vi.mocked(jwtUtil.generateRefreshToken).mockReturnValue("refresh_token")

            const result = await signIn(signInData)

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { username: "johndoe" },
            })
            expect(passwordUtil.comparePassword).toHaveBeenCalledWith(
                "password123",
                "hashed_password"
            )
            expect(result.accessToken).toBe("access_token")
            expect(result.refreshToken).toBe("refresh_token")
            expect(result.user).not.toHaveProperty("password")
        })

        it("should throw error if user is not found", async () => {
            vi.mocked(prisma.user.findUnique).mockResolvedValue(null)

            await expect(signIn({ username: "wrong", password: "p" })).rejects.toThrow(
                "Credenciais inválidas"
            )
        })

        it("should throw error if password is wrong", async () => {
            vi.mocked(prisma.user.findUnique).mockResolvedValue({ password: "hashed" } as any)
            vi.mocked(passwordUtil.comparePassword).mockResolvedValue(false)

            await expect(signIn({ username: "u", password: "wrong" })).rejects.toThrow(
                "Credenciais inválidas"
            )
        })
    })

    describe("refresh", () => {
        it("should return new tokens when refresh token is valid", async () => {
            const refreshToken = "valid_refresh_token"
            const payload = { sub: "user-id" }
            const user = { id: "user-id", username: "johndoe", role: "USER" }

            vi.mocked(jwtUtil.verifyToken).mockReturnValue(payload as any)
            vi.mocked(prisma.user.findUnique).mockResolvedValue(user as any)
            vi.mocked(jwtUtil.generateAccessToken).mockReturnValue("new_access_token")
            vi.mocked(jwtUtil.generateRefreshToken).mockReturnValue("new_refresh_token")

            const result = await refresh(refreshToken)

            expect(jwtUtil.verifyToken).toHaveBeenCalledWith(refreshToken, "refresh")
            expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { id: "user-id" } })
            expect(result.accessToken).toBe("new_access_token")
            expect(result.refreshToken).toBe("new_refresh_token")
        })

        it("should throw error if payload is invalid", async () => {
            vi.mocked(jwtUtil.verifyToken).mockReturnValue(null as any)

            await expect(refresh("invalid")).rejects.toThrow("Token inválido ou expirado")
        })

        it("should throw error if user is not found", async () => {
            vi.mocked(jwtUtil.verifyToken).mockReturnValue({ sub: "no-one" } as any)
            vi.mocked(prisma.user.findUnique).mockResolvedValue(null)

            await expect(refresh("token")).rejects.toThrow("Token inválido ou expirado")
        })
    })
})
