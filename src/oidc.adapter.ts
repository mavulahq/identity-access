import type { Adapter, AdapterPayload } from 'oidc-provider';
import type { Prisma } from '../generated/prisma/index.js';
import { PrismaService } from './prisma.service.js';

export function prismaAdapterFactory(prisma: PrismaService) {
  return class PrismaOidcAdapter implements Adapter {
    constructor(readonly model: string) {}

    async upsert(id: string, payload: AdapterPayload, expiresIn: number) {
      const data = {
        payload: payload as Prisma.InputJsonValue,
        grantId: payload.grantId,
        userCode: payload.userCode,
        uid: payload.uid,
        expiresAt: expiresIn ? new Date(Date.now() + expiresIn * 1000) : null,
        consumedAt: payload.consumed ? new Date(Number(payload.consumed) * 1000) : null,
      };
      await prisma.oidcArtifact.upsert({
        where: { model_id: { model: this.model, id } },
        create: { model: this.model, id, ...data },
        update: data,
      });
    }

    async find(id: string) {
      const artifact = await prisma.oidcArtifact.findUnique({
        where: { model_id: { model: this.model, id } },
      });
      return this.payload(artifact);
    }

    async findByUserCode(userCode: string) {
      return this.payload(await prisma.oidcArtifact.findFirst({ where: { model: this.model, userCode } }));
    }

    async findByUid(uid: string) {
      return this.payload(await prisma.oidcArtifact.findFirst({ where: { model: this.model, uid } }));
    }

    async consume(id: string) {
      await prisma.oidcArtifact.updateMany({
        where: { model: this.model, id },
        data: { consumedAt: new Date() },
      });
    }

    async destroy(id: string) {
      await prisma.oidcArtifact.deleteMany({ where: { model: this.model, id } });
    }

    async revokeByGrantId(grantId: string) {
      await prisma.oidcArtifact.deleteMany({ where: { grantId } });
    }

    async payload(
      artifact: { payload: Prisma.JsonValue; expiresAt: Date | null; consumedAt: Date | null } | null,
    ): Promise<AdapterPayload | undefined> {
      if (!artifact) return undefined;
      if (artifact.expiresAt && artifact.expiresAt.getTime() <= Date.now()) return undefined;
      const payload = artifact.payload as AdapterPayload;
      if (artifact.consumedAt) payload.consumed = Math.floor(artifact.consumedAt.getTime() / 1000);
      return payload;
    }
  };
}
